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
from pivtool.piv import PivError, DeviceGoneError
from pivtool.storage import settings, SETTINGS
from pivtool.view.utils import Dialog, get_text
from pivtool.view.generate_dialog import GenerateKeyDialog
from datetime import datetime
from functools import partial

SLOTS = {
    '9a': 'Authentication',
    '9c': 'Digital Signature',
    '9d': 'Key Management',
    '9e': 'Card Authentication',
}

USAGES = {
    '9a': m.usage_9a,
    '9c': m.usage_9c,
    '9d': m.usage_9d,
    '9e': m.usage_9e,
}

FILE_FILTER = 'Certificate/key files ' \
    '(*.pfx *.p12 *.cer *.crt *.key *.pem *.der)'


def detect_type(data, fn):
    suffix = '.' in fn and fn.lower().rsplit('.', 1)[1]
    f_format = None  # pfx, pem or der
    f_type = 0  # 1 for certificate, 2 for key
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
            certs = QtNetwork.QSslCertificate.fromData(
                data, QtNetwork.QSsl.Der)
            f_type = 1 if certs else 2
    return f_type, f_format, needs_password


def import_file(controller, slot, fn):
    with open(fn, 'rb') as f:
        data = f.read()

    f_type, f_format, needs_password = detect_type(data, fn)

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


class CertPanel(QtGui.QWidget):

    def __init__(self, controller, slot, parent=None):
        super(CertPanel, self).__init__(parent)

        self._controller = controller
        self._slot = slot
        controller.use(self._build_ui)

    def _build_ui(self, controller):
        cert = controller.get_certificate(self._slot)

        layout = QtGui.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        status = QtGui.QGridLayout()
        status.addWidget(QtGui.QLabel(m.issued_to_label), 0, 0)
        issued_to = cert.subjectInfo(QtNetwork.QSslCertificate.CommonName)
        status.addWidget(QtGui.QLabel(issued_to), 0, 1)
        status.addWidget(QtGui.QLabel(m.issued_by_label), 0, 2)
        issued_by = cert.issuerInfo(QtNetwork.QSslCertificate.CommonName)
        status.addWidget(QtGui.QLabel(issued_by), 0, 3)
        status.addWidget(QtGui.QLabel(m.valid_from_label), 1, 0)
        valid_from = QtGui.QLabel(cert.effectiveDate().toString())
        now = datetime.utcnow()
        if cert.effectiveDate().toPython() > now:
            valid_from.setStyleSheet('QLabel { color: red; }')
        status.addWidget(valid_from, 1, 1)
        status.addWidget(QtGui.QLabel(m.valid_to_label), 1, 2)
        valid_to = QtGui.QLabel(cert.expiryDate().toString())
        if cert.expiryDate().toPython() < now:
            valid_to.setStyleSheet('QLabel { color: red; }')
        status.addWidget(valid_to, 1, 3)

        layout.addLayout(status)
        buttons = QtGui.QHBoxLayout()

        export_btn = QtGui.QPushButton(m.export_to_file)
        export_btn.clicked.connect(partial(self._export_cert, cert))
        buttons.addWidget(export_btn)

        delete_btn = QtGui.QPushButton(m.delete_cert)
        delete_btn.clicked.connect(
            self._controller.wrap(self._delete_cert, True))
        buttons.addWidget(delete_btn)
        layout.addStretch()
        layout.addLayout(buttons)

    def _export_cert(self, cert):
        fn, fn_filter = QtGui.QFileDialog.getSaveFileName(
            self, m.export_cert, filter='Certificate (*.pem, *.crt)')
        if not fn:
            return

        with open(fn, 'w') as f:
            f.write(cert.toPem().data())
        QtGui.QMessageBox.information(self, m.cert_exported,
                                      m.cert_exported_desc_1 % fn)

    def _delete_cert(self, controller, release):
        res = QtGui.QMessageBox.warning(self, m.delete_cert,
                                        m.delete_cert_warning_1 % self._slot,
                                        QtGui.QMessageBox.Ok,
                                        QtGui.QMessageBox.Cancel)
        if res == QtGui.QMessageBox.Ok:
            try:
                controller.ensure_authenticated()
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(
                    m.deleting_cert,
                    (controller.delete_certificate, self._slot),
                    partial(self._delete_cert_callback, controller, release),
                    True)
            except (DeviceGoneError, PivError, ValueError) as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))

    def _delete_cert_callback(self, controller, release, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.window().accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.parent().refresh(controller)
            QtGui.QMessageBox.information(self, m.cert_deleted,
                                          m.cert_deleted_desc)


class CertWidget(QtGui.QWidget):

    def __init__(self, controller, slot):
        super(CertWidget, self).__init__()

        self._controller = controller
        self._slot = slot

        self._build_ui()

        controller.use(self.refresh)

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)

        self._status = QtGui.QLabel(m.cert_not_loaded)
        layout.addWidget(self._status)

        buttons = QtGui.QHBoxLayout()

        from_file_btn = QtGui.QPushButton(m.import_from_file)
        from_file_btn.clicked.connect(
            self._controller.wrap(self._import_file, True))
        if settings[SETTINGS.ENABLE_IMPORT]:
            buttons.addWidget(from_file_btn)

        generate_btn = QtGui.QPushButton(m.generate_key)
        generate_btn.clicked.connect(
            self._controller.wrap(self._generate_key, True))
        buttons.addWidget(generate_btn)

        layout.addLayout(buttons)

    def refresh(self, controller):
        if controller.pin_blocked:
            self.window().accept()
            return

        self.layout().removeWidget(self._status)
        self._status.hide()
        if self._slot in controller.certs:
            self._status = CertPanel(self._controller, self._slot, self)
        else:
            self._status = QtGui.QLabel('%s<br><br>%s' % (
                USAGES[self._slot], m.cert_not_loaded))
            self._status.setWordWrap(True)
        self.layout().insertWidget(0, self._status)

    def _import_file(self, controller, release):
        res = QtGui.QMessageBox.warning(self, m.import_from_file,
                                        m.import_from_file_warning_1 %
                                        self._slot,
                                        QtGui.QMessageBox.Ok,
                                        QtGui.QMessageBox.Cancel)
        if res != QtGui.QMessageBox.Ok:
            return

        fn, fn_filter = QtGui.QFileDialog.getOpenFileName(
            self, m.import_from_file, filter=FILE_FILTER)
        if not fn:
            return

        func, needs_password = import_file(controller, self._slot, fn)
        if func is None:
            QtGui.QMessageBox.warning(self, m.error, m.unsupported_file)
            return
        if needs_password:
            password, status = get_text(
                self, m.enter_file_password, m.password_label,
                QtGui.QLineEdit.Password)
            if not status:
                return
            func = (func, password)

        try:
            controller.ensure_authenticated()
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(m.importing_file, func, partial(
                self._import_file_callback, controller, release), True)
        except (DeviceGoneError, PivError, ValueError) as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))

    def _import_file_callback(self, controller, release, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.window().accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.refresh(controller)
            QtGui.QMessageBox.information(self, m.cert_installed,
                                          m.cert_installed_desc)

    def _generate_key(self, controller, release):
        dialog = GenerateKeyDialog(controller, self._slot, self)
        if dialog.exec_():
            self.refresh(controller)


class CertDialog(Dialog):

    def __init__(self, controller, parent=None):
        super(CertDialog, self).__init__(parent)
        self.setWindowTitle(m.certificates)

        self._complex = settings[SETTINGS.COMPLEX_PINS]
        self._controller = controller
        controller.use(self._build_ui)
        controller.on_lost(self.accept)

    def showEvent(self, event):
        self.move(self.x() + 15, self.y() + 15)
        event.accept()

    def _build_ui(self, controller):
        layout = QtGui.QVBoxLayout(self)
        # This unfortunately causes the window to resize when switching tabs.
        # layout.setSizeConstraint(QtGui.QLayout.SetFixedSize)

        self._cert_tabs = QtGui.QTabWidget()
        self._cert_tabs.setMinimumSize(540, 160)
        shown_slots = settings[SETTINGS.SHOWN_SLOTS]
        selected = False
        for (slot, label) in sorted(SLOTS.items()):
            if slot in shown_slots:
                index = self._cert_tabs.addTab(
                    CertWidget(self._controller, slot), label)
                if not selected:
                    self._cert_tabs.setCurrentIndex(index)
                    selected = True
            elif not settings.is_locked(SETTINGS.SHOWN_SLOTS):
                index = self._cert_tabs.addTab(QtGui.QLabel(), label)
                self._cert_tabs.setTabEnabled(index, False)
        layout.addWidget(self._cert_tabs)
