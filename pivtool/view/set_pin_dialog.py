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
from pivtool.utils import complexity_check


PIN_VALIDATOR = QtGui.QRegExpValidator(QtCore.QRegExp(r'.{6,8}'))


def _pin_field():
    field = QtGui.QLineEdit()
    field.setEchoMode(QtGui.QLineEdit.Password)
    field.setMaxLength(8)
    field.setValidator(PIN_VALIDATOR)
    return field


class SetPinDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(SetPinDialog, self).__init__(parent)

        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.change_pin_desc))

        layout.addWidget(QtGui.QLabel(m.current_pin_label))
        self._old_pin = _pin_field()
        layout.addWidget(self._old_pin)
        layout.addWidget(QtGui.QLabel(m.new_pin_label))
        self._new_pin = _pin_field()
        layout.addWidget(self._new_pin)
        layout.addWidget(QtGui.QLabel(m.verify_pin_label))
        self._confirm_pin = _pin_field()
        layout.addWidget(self._confirm_pin)

        self._new_pin.textChanged.connect(self._check_confirm)
        self._confirm_pin.textChanged.connect(self._check_confirm)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        self._ok_btn.setDisabled(True)
        buttons.accepted.connect(self._set_pin)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def _check_confirm(self):
        new_pin = self._new_pin.text()
        if len(new_pin) > 0 and new_pin == self._confirm_pin.text():
            self._ok_btn.setDisabled(False)
        else:
            self._ok_btn.setDisabled(True)

    def _set_pin(self):
        old_pin = self._old_pin.text()
        new_pin = self._new_pin.text()
        if not complexity_check(new_pin):
            QtGui.QMessageBox.warning(self, m.pin_not_complex,
                                      m.pin_complexity_desc)
            return

        worker = QtCore.QCoreApplication.instance().worker
        worker.post(m.changing_pin,
                    (self._controller.change_pin, old_pin, new_pin),
                    self._change_pin_callback, True)

    def _change_pin_callback(self, result):
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
            raise result
        else:
            self.accept()
