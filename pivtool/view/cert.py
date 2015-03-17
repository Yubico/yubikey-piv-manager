# Copyright (c) 2014 Yubico AB
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, We grant you additional
# permission to convey the resulting work. Corresponding Source for a
# non-source form of such a combination shall include the source code
# for the parts of OpenSSL used as well as that of the covered work.

from PySide import QtGui, QtCore, QtNetwork
from pivtool import messages as m
from pivtool.utils import HAS_AD
from pivtool.piv import DeviceGoneError
from pivtool.storage import settings, SETTINGS
from datetime import datetime
from functools import partial

SLOTS = {
    '9a': 'Authentication',
    '9c': 'Digital Signature',
    '9d': 'Key Management',
    '9e': 'Card Authentication',
}

FILE_FILTER = "Certificate/key files " \
    "(*.pfx *.p12 *.cer *.crt *.key *.pem *.der)"


def import_file(controller, slot, fn):
    suffix = '.' in fn and fn.lower().rsplit('.', 1)[1]
    with open(fn, 'r') as f:
        data = f.read()

    f_format = None
    f_type = 0
    needs_password = False
    if suffix in ['pfx', 'p12']:
        f_format = 'pfx'
        needs_password = True
    else:
        f_format = 'pem' if data.startswith('-----') else 'der'
        if f_format == 'pem':
            first_line = data.splitlines()[0]
            f_type = 1 if 'CERTIFICATE' in first_line else 2
            needs_password = 'ENCRYPTED' in first_line
        elif suffix in ['cer', 'crt']:
            f_type = 1
        elif suffix in ['key']:
            f_type = 2
        else:
            certs = QtNetwork.QSslCertificate.fromData(data, QtNetwork.QSsl.Der)
            f_type = 1 if certs else 2

    if f_type == 2 and f_format == 'der':
        return None, None  # We don't know what type of key this is.

    def func(password=None):
        if f_format == 'pfx':
            controller.import_key(data, slot, 'PKCS12', password)
            controller.import_certificate(data, slot, 'PKCS12', password)
        elif f_format == 'pem':
            if f_type == 1:
                controller.import_certificate(data, slot, 'PEM', password)
            elif f_type == 2:
                controller.import_key(data, slot, 'PEM', password)
        else:
            controller.import_certificate(data, slot, 'DER')

    return func, needs_password


class CertWidget(QtGui.QWidget):

    def __init__(self, controller, slot):
        super(CertWidget, self).__init__()

        self._controller = controller
        self._slot = slot

        self.refresh()

    def _build_no_cert_ui(self):
        layout = QtGui.QVBoxLayout(self)

        layout.addWidget(QtGui.QLabel(m.cert_not_loaded))

        # TODO: Add buttons for generate key?, CSR?
        buttons = QtGui.QHBoxLayout()
        from_ca_btn = QtGui.QPushButton(m.change_cert)
        from_ca_btn.clicked.connect(self._request_cert)
        if HAS_AD:
            buttons.addWidget(from_ca_btn)

        from_file_btn = QtGui.QPushButton(m.import_from_file)
        from_file_btn.clicked.connect(self._import_file)
        buttons.addWidget(from_file_btn)

        layout.addLayout(buttons)

        layout.addStretch()

    def _build_cert_ui(self, cert):
        layout = QtGui.QVBoxLayout(self)

        status = QtGui.QGridLayout()
        status.addWidget(QtGui.QLabel(m.issued_to_label), 0, 0)
        subject = QtGui.QLabel(cert.issued_to)
        status.addWidget(subject, 0, 1)
        status.addWidget(QtGui.QLabel(m.issued_by_label), 0, 2)
        issuer = QtGui.QLabel(cert.issued_by)
        status.addWidget(issuer, 0, 3)
        status.addWidget(QtGui.QLabel(m.valid_from_label), 1, 0)
        valid_from = QtGui.QLabel(cert.effectiveDate().toString())
        now = datetime.now()
        if cert.effectiveDate().toPython() > now:
            valid_from.setStyleSheet("QLabel { color: red; }")
        status.addWidget(valid_from, 1, 1)
        status.addWidget(QtGui.QLabel(m.valid_to_label), 1, 2)
        valid_to = QtGui.QLabel(cert.expiryDate().toString())
        if cert.expiryDate().toPython() < now:
            valid_to.setStyleSheet("QLabel { color: red; }")
        status.addWidget(valid_to, 1, 3)

        layout.addLayout(status)
        buttons = QtGui.QHBoxLayout()

        export_btn = QtGui.QPushButton(m.export_to_file)
        export_btn.clicked.connect(partial(self._export_cert, cert))
        buttons.addWidget(export_btn)

        delete_btn = QtGui.QPushButton(m.delete_cert)
        delete_btn.clicked.connect(self._delete_cert)
        buttons.addWidget(delete_btn)
        layout.addLayout(buttons)

        layout.addStretch()

    def refresh(self):
        cert = self._controller.get_certificate(self._slot)
        QtGui.QWidget().setLayout(self.layout())  # Get rid of old layout.
        if cert is None:
            self._build_no_cert_ui()
        else:
            self._build_cert_ui(cert)

    def _export_cert(self, cert):
        fn, fn_filter = QtGui.QFileDialog.getSaveFileName(
            self, m.export_cert, filter='PEM files (*.pem)')
        if not fn:
            return

        with open(fn, 'w') as f:
            f.write(cert.toPem().data())
        QtGui.QMessageBox.information(self, m.cert_exported,
                                      m.cert_exported_desc_1 % fn)

    def _delete_cert(self):
        res = QtGui.QMessageBox.warning(self, m.delete_cert,
                                        m.delete_cert_warning_1 % self._slot,
                                        QtGui.QMessageBox.Ok,
                                        QtGui.QMessageBox.Cancel)
        if res == QtGui.QMessageBox.Ok:
            try:
                self._controller.ensure_authenticated()
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(m.deleting_cert, (
                    self._controller.delete_certificate, self._slot),
                    self._delete_cert_callback, True)
            except ValueError as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))

    def _delete_cert_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.window().accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.refresh()
            QtGui.QMessageBox.information(self, m.cert_deleted,
                                          m.cert_deleted_desc)

    def _import_file(self):
        fn, fn_filter = QtGui.QFileDialog.getOpenFileName(
            self, m.import_from_file, filter=FILE_FILTER)
        if not fn:
            return

        func, needs_password = import_file(self._controller, self._slot, fn)
        if func is None:
            QtGui.QMessageBox.warning(self, m.error, m.unsupported_file)
            return
        if needs_password:
            password, status = QtGui.QInputDialog.getText(
                self, m.enter_file_password, m.password_label,
                QtGui.QLineEdit.Password)
            if not status:
                return
            func = (func, password)

        try:
            self._controller.ensure_authenticated()
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(m.importing_file, func, self._import_file_callback,
                        True)
        except ValueError as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))

    def _import_file_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.window().accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.refresh()
            QtGui.QMessageBox.information(self, m.cert_installed,
                                          m.cert_installed_desc)

    def _request_cert(self):
        res = QtGui.QMessageBox.warning(self, m.change_cert,
                                        m.change_cert_warning_1 % self._slot,
                                        QtGui.QMessageBox.Ok,
                                        QtGui.QMessageBox.Cancel)
        if res == QtGui.QMessageBox.Ok:
            pin, status = QtGui.QInputDialog.getText(
                self, m.enter_pin, m.pin_label, QtGui.QLineEdit.Password)
            if not status:
                return

            cert_tmpl = settings.get(SETTINGS.CERTREQ_TEMPLATE)
            if cert_tmpl is None:
                # Ask for certificate template
                cert_tmpl, status = QtGui.QInputDialog.getText(
                    self, m.cert_tmpl, m.cert_tmpl)
                if not status:
                    return

            try:
                self._controller.ensure_authenticated(pin)
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(m.changing_cert, (
                    self._controller.request_certificate, pin, cert_tmpl,
                    self._slot), self._request_cert_callback, True)
            except ValueError as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))

    def _request_cert_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.window().accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.refresh()
            QtGui.QMessageBox.information(self, m.cert_installed,
                                          m.cert_installed_desc)


class CertDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(CertDialog, self).__init__(parent)
        self.setWindowTitle(m.certificates)
        self.setFixedSize(540, 180)

        self._complex = settings.get(SETTINGS.COMPLEX_PINS, False)
        self._controller = controller
        self._build_ui()

    def showEvent(self, event):
        self.move(self.x() + 15, self.y() + 15)
        event.accept()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()

        self._cert_tabs = QtGui.QTabWidget()
        for (slot, label) in SLOTS.items():
            self._cert_tabs.addTab(CertWidget(self._controller, slot), label)
        layout.addWidget(self._cert_tabs)

        self.setLayout(layout)
