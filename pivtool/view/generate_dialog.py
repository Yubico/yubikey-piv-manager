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

from PySide import QtGui, QtCore
from pivtool import messages as m
from pivtool.utils import has_ca, request_cert_from_ca
from pivtool.storage import settings, SETTINGS
from pivtool.view.utils import Headers


def save_file_as(parent, title, fn_filter):
    return QtGui.QFileDialog.getSaveFileName(parent, title, filter=fn_filter)[0]


class GenerateKeyDialog(QtGui.QDialog):

    def __init__(self, controller, slot, parent=None):
        super(GenerateKeyDialog, self).__init__(parent)

        self._controller = controller
        self._slot = slot
        self._build_ui()

    def _build_ui(self):
        self.setWindowFlags(self.windowFlags()
                            ^ QtCore.Qt.WindowContextHelpButtonHint)
        self.setWindowTitle(m.generate_key)
        self.setFixedWidth(400)

        headers = Headers()
        layout = QtGui.QVBoxLayout(self)

        warning = QtGui.QLabel(m.generate_key_warning_1 % self._slot)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self._alg_type = QtGui.QButtonGroup(self)
        self._alg_rsa_1024 = QtGui.QRadioButton(m.alg_rsa_1024)
        self._alg_rsa_2048 = QtGui.QRadioButton(m.alg_rsa_2048)
        self._alg_rsa_2048.setChecked(True)
        self._alg_rsa_2048.setFocus()
        self._alg_ecc_p256 = QtGui.QRadioButton(m.alg_ecc_p256)
        self._alg_type.addButton(self._alg_rsa_1024)
        self._alg_type.addButton(self._alg_rsa_2048)
        self._alg_type.addButton(self._alg_ecc_p256)
        force_algo = settings[SETTINGS.FORCE_ALGORITHM]
        if force_algo is None:
            layout.addWidget(headers.section(m.algorithm))
            layout.addWidget(self._alg_rsa_1024)
            layout.addWidget(self._alg_rsa_2048)
            layout.addWidget(self._alg_ecc_p256)
        else:
            layout.addWidget(QtGui.QLabel(m.algorithm_1 % force_algo))

        layout.addWidget(headers.section(m.output))
        self._out_type = QtGui.QButtonGroup(self)
        self._out_pk = QtGui.QRadioButton(m.out_pk)
        self._out_csr = QtGui.QRadioButton(m.out_csr)
        self._out_ssc = QtGui.QRadioButton(m.out_ssc)
        self._out_type.addButton(self._out_pk)
        self._out_type.addButton(self._out_ssc)
        self._out_type.addButton(self._out_csr)
        if settings[SETTINGS.ENABLE_OUT_PK]:
            layout.addWidget(self._out_pk)
            self._out_pk.setChecked(True)
        if settings[SETTINGS.ENABLE_OUT_SSC]:
            layout.addWidget(self._out_ssc)
            self._out_ssc.setChecked(True)
        if settings[SETTINGS.ENABLE_OUT_CSR]:
            layout.addWidget(self._out_csr)
            if self._out_type.checkedButton() is None:
                self._out_csr.setChecked(True)

        self._out_ca = QtGui.QRadioButton(m.out_ca)
        self._subject = QtGui.QLineEdit(settings.get(SETTINGS.SUBJECT))
        if not settings.is_locked(SETTINGS.SUBJECT):
            layout.addWidget(self._subject)
        self._cert_tmpl = QtGui.QLineEdit(
            settings.get(SETTINGS.CERTREQ_TEMPLATE))
        if settings[SETTINGS.ENABLE_OUT_CA]:
            if has_ca():
                self._out_type.addButton(self._out_ca)
                self._out_ca.setChecked(True)
                layout.addWidget(self._out_ca)
                if not settings.is_locked(SETTINGS.CERTREQ_TEMPLATE):
                    self._cert_tmpl.setDisabled(True)
                    cert_box = QtGui.QHBoxLayout()
                    cert_box.addWidget(QtGui.QLabel(m.cert_tmpl))
                    cert_box.addWidget(self._cert_tmpl)
                    layout.addLayout(cert_box)
            else:
                layout.addWidget(m.ca_not_connected)

        self._out_type.buttonClicked.connect(self._output_changed)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)

        checked_btn = self._out_type.checkedButton()
        if checked_btn is None:
            layout.addWidget(QtGui.QLabel(m.no_output))
            buttons.button(QtGui.QDialogButtonBox.Ok).setDisabled(True)
        else:
            self._output_changed(checked_btn)
        buttons.accepted.connect(self._generate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _output_changed(self, btn):
        self._cert_tmpl.setEnabled(btn is self._out_ca)
        self._subject.setDisabled(btn is self._out_pk)

    @property
    def algorithm(self):
        algo = settings[SETTINGS.FORCE_ALGORITHM]
        if algo is not None:
            return algo
        btn = self._alg_type.checkedButton()
        if btn is self._alg_rsa_1024:
            return 'RSA1024'
        if btn is self._alg_rsa_2048:
            return 'RSA2048'
        if btn is self._alg_ecc_p256:
            return 'ECCP256'

    def _generate(self):
        out_fmt = self._out_type.checkedButton()

        if not out_fmt:
            QtGui.QMessageBox.warning(self, m.no_output, m.no_output_desc)
            self.accept()
            return

        if out_fmt is self._out_pk:
            out_fn = save_file_as(self, m.save_pk, 'Public Key (*.pem)')
            if not out_fn:
                return
        elif out_fmt is self._out_csr:
            out_fn = save_file_as(self, m.save_csr,
                                  'Certificate Signing Reqest (*.csr)')
            if not out_fn:
                return
        else:
            out_fn = None

        try:
            if out_fmt is not self._out_pk:
                pin = self._controller.ensure_pin()
            else:
                pin = None
            self._controller.ensure_authenticated(pin)
        except Exception as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))
            self.accept()
            return

        worker = QtCore.QCoreApplication.instance().worker
        worker.post(m.generating_key, (self._do_generate, out_fmt, pin, out_fn),
                    self._generate_callback, True)

    def _do_generate(self, out_fmt, pin=None, out_fn=None):
        data = self._controller.generate_key(self._slot, self.algorithm)
        subject = self._subject.text()
        if out_fmt in [self._out_csr, self._out_ca]:
            data = self._controller.create_csr(self._slot, pin, data, subject)

        if out_fmt in [self._out_pk, self._out_csr]:
            with open(out_fn, 'w') as f:
                f.write(data)
            return out_fn
        else:
            if out_fmt is self._out_ssc:
                cert = self._controller.selfsign_certificate(
                    self._slot, pin, data, subject)
            elif out_fmt is self._out_ca:
                cert = request_cert_from_ca(data, self._cert_tmpl.text())
            self._controller.import_certificate(cert, self._slot)

    def _generate_callback(self, result):
        self.accept()
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            out_fmt = self._out_type.checkedButton()
            message = m.generated_key_desc_1 % self._slot
            if out_fmt is self._out_pk:
                message += '\n' + m.gen_out_pk_1 % result
            elif out_fmt is self._out_csr:
                message += '\n' + m.gen_out_csr_1 % result
            elif out_fmt is self._out_ssc:
                message += '\n' + m.gen_out_ssc
            elif out_fmt is self._out_ca:
                message += '\n' + m.gen_out_ca

            QtGui.QMessageBox.information(self, m.generated_key, message)
