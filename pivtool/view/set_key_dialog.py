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
from pivtool.piv import DeviceGoneError, KEY_LEN
from pivtool.view.utils import TOP_SECTION, SECTION, KEY_VALIDATOR, pin_field
from pivtool.utils import complexity_check
from pivtool.storage import settings, SETTINGS
import os


class SetKeyDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(SetKeyDialog, self).__init__(parent)

        self._controller = controller
        self._build_ui()

        kt = self._kt_pin if self._controller.pin_is_key else self._kt_key
        kt.setChecked(True)
        self._change_key_type(kt)

    def _build_ui(self):
        self.setWindowTitle(m.change_key)
        self.setMinimumWidth(400)

        layout = QtGui.QVBoxLayout(self)

        self._current_key = QtGui.QLineEdit()
        self._current_key.setValidator(KEY_VALIDATOR)
        self._current_key.textChanged.connect(self._validate)
        if not self._controller.pin_is_key:
            layout.addWidget(QtGui.QLabel(m.current_key_label))
            layout.addWidget(self._current_key)

        self._key_type = QtGui.QButtonGroup(self)
        self._kt_pin = QtGui.QRadioButton(m.use_pin_as_key, self)
        self._kt_key = QtGui.QRadioButton(m.use_separate_key, self)
        self._key_type.addButton(self._kt_pin)
        self._key_type.addButton(self._kt_key)
        self._key_type.buttonClicked.connect(self._change_key_type)
        layout.addWidget(self._kt_pin)
        layout.addWidget(self._kt_key)

        layout.addWidget(QtGui.QLabel(m.new_key_label))
        self._key = QtGui.QLineEdit()
        self._key.setValidator(KEY_VALIDATOR)
        self._key.textChanged.connect(self._validate)
        layout.addWidget(self._key)

        buttons = QtGui.QDialogButtonBox()
        self._randomize_btn = QtGui.QPushButton(m.randomize)
        self._randomize_btn.clicked.connect(self.randomize)
        self._copy_btn = QtGui.QPushButton(m.copy_clipboard)
        self._copy_btn.clicked.connect(self._copy)
        buttons.addButton(self._randomize_btn,
                          QtGui.QDialogButtonBox.ActionRole)
        buttons.addButton(self._copy_btn, QtGui.QDialogButtonBox.ActionRole)
        layout.addWidget(buttons)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        self._ok_btn.setDisabled(True)
        buttons.accepted.connect(self._set_key)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def use_pin(self):
        return self._key_type.checkedButton() == self._kt_pin

    def _change_key_type(self, btn):
        if btn == self._kt_pin:
            self._key.setText('')
            self._key.setEnabled(False)
            self._randomize_btn.setEnabled(False)
            self._copy_btn.setEnabled(False)
        else:
            self.randomize()
            self._key.setEnabled(True)
            self._randomize_btn.setEnabled(True)
            self._copy_btn.setEnabled(True)
        self._validate()

    def randomize(self):
        self._key.setText(os.urandom(KEY_LEN).encode('hex'))

    def _copy(self):
        self._key.selectAll()
        self._key.copy()
        self._key.deselect()

    def _validate(self):
        old_ok = self._controller.pin_is_key \
            or self._current_key.hasAcceptableInput()
        new_ok = self.use_pin or self._key.hasAcceptableInput()

        self._copy_btn.setEnabled(not self.use_pin and new_ok)
        self._ok_btn.setEnabled(old_ok and new_ok)

    def _set_key(self):
        if self.use_pin and self._controller.pin_is_key:
            self.reject()
            return

        if not self._controller.puk_blocked and self.use_pin:
            res = QtGui.QMessageBox.warning(self, m.block_puk,
                                            m.block_puk_desc,
                                            QtGui.QMessageBox.Ok,
                                            QtGui.QMessageBox.Cancel)
            if res != QtGui.QMessageBox.Ok:
                return


        if self._controller.pin_is_key or self.use_pin:
            pin, status = QtGui.QInputDialog.getText(self, m.enter_pin,
                                                     m.pin_label,
                                                     QtGui.QLineEdit.Password)
            if not status:
                return
        else:
            pin = None

        current_key = pin \
            if self._controller.pin_is_key else self._current_key.text()
        new_key = pin if self.use_pin else self._key.text()

        self._controller.ensure_authenticated(current_key)
        worker = QtCore.QCoreApplication.instance().worker
        worker.post(m.changing_key, (self._controller.set_authentication,
                                     new_key, self.use_pin),
                    self._set_key_callback, True)

    def _set_key_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.accept()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.accept()
