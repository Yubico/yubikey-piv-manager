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
from pivman import messages as m
from pivman.utils import has_ca, request_cert_from_ca
from pivman.storage import settings, SETTINGS
from pivman.piv import DeviceGoneError
from pivman.view.usage_policy_dialog import UsagePolicyDialog
from pivman.view.utils import SUBJECT_VALIDATOR


def save_file_as(parent, title, fn_filter):
    return QtGui.QFileDialog.getSaveFileName(parent, title, filter=fn_filter)[0]


def needs_subject(forms):
    return bool({'csr', 'ssc', 'ca'}.intersection(forms))


class GenerateKeyDialog(UsagePolicyDialog):

    def __init__(self, controller, slot, parent=None):
        super(GenerateKeyDialog, self).__init__(controller, slot, parent)

    def _build_ui(self):
        self.setWindowTitle(m.generate_key)
        self.setFixedWidth(400)

        layout = QtGui.QVBoxLayout(self)

        warning = QtGui.QLabel(m.generate_key_warning_1 % self._slot)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self._build_algorithms(layout)
        self._build_usage_policy(layout)
        self._build_output(layout)

    def _build_algorithms(self, layout):
        self._alg_type = QtGui.QButtonGroup(self)
        self._alg_rsa_1024 = QtGui.QRadioButton(m.alg_rsa_1024)
        self._alg_rsa_1024.setProperty('value', 'RSA1024')
        self._alg_rsa_2048 = QtGui.QRadioButton(m.alg_rsa_2048)
        self._alg_rsa_2048.setProperty('value', 'RSA2048')
        self._alg_ecc_p256 = QtGui.QRadioButton(m.alg_ecc_p256)
        self._alg_ecc_p256.setProperty('value', 'ECCP256')
        self._alg_ecc_p384 = QtGui.QRadioButton(m.alg_ecc_p384)
        self._alg_ecc_p384.setProperty('value', 'ECCP384')
        self._alg_type.addButton(self._alg_rsa_1024)
        self._alg_type.addButton(self._alg_rsa_2048)
        self._alg_type.addButton(self._alg_ecc_p256)
        if self._controller.version_tuple >= (4, 0, 0):
            self._alg_type.addButton(self._alg_ecc_p384)
        algo = settings[SETTINGS.ALGORITHM]
        if settings.is_locked(SETTINGS.ALGORITHM):
            layout.addWidget(QtGui.QLabel(m.algorithm_1 % algo))
        else:
            layout.addWidget(self.section(m.algorithm))
            for button in self._alg_type.buttons():
                layout.addWidget(button)
                if button.property('value') == algo:
                    button.setChecked(True)
                    button.setFocus()
            if not self._alg_type.checkedButton():
                button = self._alg_type.buttons()[0]
                button.setChecked(True)

    def _build_output(self, layout):
        layout.addWidget(self.section(m.output))
        self._out_type = QtGui.QButtonGroup(self)
        self._out_pk = QtGui.QRadioButton(m.out_pk)
        self._out_pk.setProperty('value', 'pk')
        self._out_ssc = QtGui.QRadioButton(m.out_ssc)
        self._out_ssc.setProperty('value', 'ssc')
        self._out_csr = QtGui.QRadioButton(m.out_csr)
        self._out_csr.setProperty('value', 'csr')
        self._out_ca = QtGui.QRadioButton(m.out_ca)
        self._out_ca.setProperty('value', 'ca')
        self._out_type.addButton(self._out_pk)
        self._out_type.addButton(self._out_ssc)
        self._out_type.addButton(self._out_csr)
        out_btns = []
        for button in self._out_type.buttons():
            value = button.property('value')
            if value in settings[SETTINGS.SHOWN_OUT_FORMS]:
                layout.addWidget(button)
                out_btns.append(button)
                if value == settings[SETTINGS.OUT_TYPE]:
                    button.setChecked(True)

        self._cert_tmpl = QtGui.QLineEdit(settings[SETTINGS.CERTREQ_TEMPLATE])
        if 'ca' in settings[SETTINGS.SHOWN_OUT_FORMS]:
            if has_ca():
                out_btns.append(self._out_ca)
                self._out_type.addButton(self._out_ca)
                self._out_ca.setChecked(True)
                layout.addWidget(self._out_ca)
                if not settings.is_locked(SETTINGS.CERTREQ_TEMPLATE):
                    cert_box = QtGui.QHBoxLayout()
                    cert_box.addWidget(QtGui.QLabel(m.cert_tmpl))
                    cert_box.addWidget(self._cert_tmpl)
                    layout.addLayout(cert_box)
            else:
                layout.addWidget(QtGui.QLabel(m.ca_not_connected))

        self._out_type.buttonClicked.connect(self._output_changed)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)

        self._subject = QtGui.QLineEdit(settings[SETTINGS.SUBJECT])
        self._subject.setValidator(SUBJECT_VALIDATOR)

        today = QtCore.QDate.currentDate()
        self._expire_date = QtGui.QDateTimeEdit(today.addYears(1))
        self._expire_date.setDisplayFormat("yyyy-MM-dd")
        self._expire_date.setMinimumDate(today.addDays(1))

        if not out_btns:
            layout.addWidget(QtGui.QLabel(m.no_output))
            buttons.button(QtGui.QDialogButtonBox.Ok).setDisabled(True)
        else:
            if not settings.is_locked(SETTINGS.SUBJECT) and \
                    needs_subject([b.property('value') for b in out_btns]):
                subject_box = QtGui.QHBoxLayout()
                subject_box.addWidget(QtGui.QLabel(m.subject))
                subject_box.addWidget(self._subject)
                layout.addLayout(subject_box)
                expire_date = QtGui.QHBoxLayout()
                expire_date.addWidget(QtGui.QLabel(m.expiration_date))
                expire_date.addWidget(self._expire_date)
                layout.addLayout(expire_date)

            out_btn = self._out_type.checkedButton()
            if out_btn is None:
                out_btn = out_btns[0]
                out_btn.setChecked(True)
            self._output_changed(out_btn)
        buttons.accepted.connect(self._generate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _output_changed(self, btn):
        self._cert_tmpl.setEnabled(btn is self._out_ca)
        self._subject.setDisabled(btn is self._out_pk)
        self._expire_date.setDisabled(btn is not self._out_ssc)

    @property
    def algorithm(self):
        if settings.is_locked(SETTINGS.ALGORITHM):
            return settings[SETTINGS.ALGORITHM]
        return self._alg_type.checkedButton().property('value')

    @property
    def out_format(self):
        return self._out_type.checkedButton().property('value')

    def _generate(self):
        if self.out_format != 'pk' and not \
                self._subject.hasAcceptableInput():
            QtGui.QMessageBox.warning(self, m.invalid_subject,
                                      m.invalid_subject_desc)
            self._subject.setFocus()
            self._subject.selectAll()
            return

        if self.out_format == 'pk':
            out_fn = save_file_as(self, m.save_pk, 'Public Key (*.pem)')
            if not out_fn:
                return
        elif self.out_format == 'csr':
            out_fn = save_file_as(self, m.save_csr,
                                  'Certificate Signing Reqest (*.csr)')
            if not out_fn:
                return
        else:
            out_fn = None

        try:
            if not self._controller.poll():
                self._controller.reconnect()

            if self.out_format != 'pk':
                pin = self._controller.ensure_pin()
            else:
                pin = None
            self._controller.ensure_authenticated(pin)
        except Exception as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))
            return

        valid_days = QtCore.QDate.currentDate().daysTo(self._expire_date.date())

        worker = QtCore.QCoreApplication.instance().worker
        worker.post(
            m.generating_key, (self._do_generate, pin, out_fn, valid_days),
            self._generate_callback, True)

    def _do_generate(self, pin=None, out_fn=None, valid_days=365):
        data = self._controller.generate_key(self._slot, self.algorithm,
                                             self.pin_policy,
                                             self.touch_policy)
        return (self._do_generate2, data, pin, out_fn, valid_days)

    def _generate_callback(self, result):
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            busy_message = m.generating_key
            if self.touch_policy and self.out_format in ['ssc', 'csr', 'ca']:
                QtGui.QMessageBox.information(self, m.touch_needed,
                                              m.touch_needed_desc)
                busy_message = m.touch_prompt
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(busy_message, result, self._generate_callback2, True)

    def _do_generate2(self, data, pin, out_fn, valid_days=365):
        subject = self._subject.text()
        if self.out_format in ['csr', 'ca']:
            data = self._controller.create_csr(self._slot, pin, data, subject)

        if self.out_format in ['pk', 'csr']:
            with open(out_fn, 'w') as f:
                f.write(data)
            return out_fn
        else:
            if self.out_format == 'ssc':
                cert = self._controller.selfsign_certificate(
                    self._slot, pin, data, subject, valid_days)
            elif self.out_format == 'ca':
                cert = request_cert_from_ca(data, self._cert_tmpl.text())
            self._controller.import_certificate(cert, self._slot)

    def _generate_callback2(self, result):
        self.accept()
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            settings[SETTINGS.ALGORITHM] = self.algorithm
            if self._controller.version_tuple >= (4, 0, 0):
                settings[SETTINGS.TOUCH_POLICY] = self.touch_policy
            settings[SETTINGS.OUT_TYPE] = self.out_format
            if self.out_format != 'pk' and not \
                    settings.is_locked(SETTINGS.SUBJECT):
                subject = self._subject.text()
                # Only save if different:
                if subject != settings[SETTINGS.SUBJECT]:
                    settings[SETTINGS.SUBJECT] = subject
            if self.out_format == 'ca':
                settings[SETTINGS.CERTREQ_TEMPLATE] = self._cert_tmpl.text()

            message = m.generated_key_desc_1 % self._slot
            if self.out_format == 'pk':
                message += '\n' + m.gen_out_pk_1 % result
            elif self.out_format == 'csr':
                message += '\n' + m.gen_out_csr_1 % result
            elif self.out_format == 'ssc':
                message += '\n' + m.gen_out_ssc
            elif self.out_format == 'ca':
                message += '\n' + m.gen_out_ca

            QtGui.QMessageBox.information(self, m.generated_key, message)
