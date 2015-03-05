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
from pivtool.piv import DeviceGoneError
from pivtool.view.utils import pin_field
from pivtool.utils import complexity_check

KEY_VALIDATOR = QtGui.QRegExpValidator(QtCore.QRegExp(r'[0-9a-fA-F]{48}'))
HEADER = "<br><b>%s</b>"


class InitDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(InitDialog, self).__init__(parent)

        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.initialize))

        layout.addLayout(self._build_pin_settings())
        layout.addLayout(self._build_key_settings())
        layout.addStretch()

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        buttons.accepted.connect(self._initialize)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def _build_pin_settings(self):
        layout = QtGui.QFormLayout()
        layout.addRow(QtGui.QLabel(HEADER % m.pin))
        self._new_pin = pin_field()
        layout.addRow(m.new_pin_label, self._new_pin)
        self._confirm_pin = pin_field()
        layout.addRow(m.verify_pin_label, self._confirm_pin)
        return layout

    def _build_key_settings(self):
        self._key_layout = QtGui.QFormLayout()
        self._key_layout.addRow(QtGui.QLabel(HEADER % m.management_key))
        self._key_type = QtGui.QComboBox()
        self._key_type.addItem(m.key_type_pin)
        self._key_type.addItem(m.key_type_password)
        self._key_type.addItem(m.key_type_key)
        self._key_layout.addRow(m.key_type_label, self._key_type)
        self._key_type.currentIndexChanged.connect(self._change_key_type)

        self._key = QtGui.QLineEdit()
        self._key.setValidator(KEY_VALIDATOR)
        self._password = QtGui.QLineEdit()
        self._password.setEchoMode(QtGui.QLineEdit.Password)
        self._password_verify = QtGui.QLineEdit()
        self._password_verify.setEchoMode(QtGui.QLineEdit.Password)
        return self._key_layout

    def _change_key_type(self, index):
        for widget in [self._key, self._password, self._password_verify]:
            widget.setText('')
            label = self._key_layout.labelForField(widget)
            if label is not None:
                self._key_layout.removeWidget(label)
                label.hide()
            self._key_layout.removeWidget(widget)
            widget.hide()
        if index == 0:  # PIN
            return

        if index == 1:  # Password
            self._key_layout.addRow(m.password_label, self._password)
            self._key_layout.addRow(m.verify_password_label, self._password_verify)
            self._password.show()
            self._password_verify.show()
            self._password.setFocus()
        else:  # Key
            self._key_layout.addRow(m.key_label, self._key)
            self._key.show()
            self._key.setFocus()

    def _validate_data(self):
        error = None

        # Check PIN
        new_pin = self._new_pin.text()
        if not new_pin:
            error = m.pin_empty
        elif new_pin != self._confirm_pin.text():
            error = m.pin_confirm_mismatch
        elif not complexity_check(new_pin):  # TODO: Only if enforced
            error = m.pin_complexity_desc

        if error:
            self._new_pin.setText('')
            self._confirm_pin.setText('')
            self._new_pin.setFocus()
            raise ValueError(error)

        # Check key
        index = self._key_type.currentIndex()
        if index == 1:  # Password
            password = self._password.text()
            if not password:
                error = m.password_empty
            elif password != self._password_verify.text():
                error = m.password_confirm_mismatch
            elif not complexity_check(password):  # TODO: Only if enforced
                error = m.pin_complexity_desc

            if error:
                self._password.setText('')
                self._password_verify.setText('')
                self._password.setFocus()
                raise ValueError(error)
        elif index == 2:  # Key
            if not self._key.hasAcceptableInput():
                self._key.setText('')
                self._key.setFocus()
                raise ValueError(m.key_invalid_desc)

    def _initialize(self):
        try:
            self._validate_data()
        except ValueError as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))
            return

        new_pin = self._new_pin.text()

        index = self._key_type.currentIndex()
        if index == 0:  # PIN
            key = None
            use_password = True
        elif index == 1:  # Password
            key = self._password.text()
            use_password = True
        else:  # Key
            if not self._key.hasAcceptableInput():
                QtGui.QMessageBox.warning(
                    self, m.key_invalid, m.key_invalid_desc)
                return
            key = self._key.text()
            use_password = False

        try:
            self._controller.ensure_authenticated()
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(
                m.initializing,
                (self._controller.initialize, new_pin, None, key, use_password),
                self._init_callback,
                True
            )
        except ValueError as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))

    def _init_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.accept()
