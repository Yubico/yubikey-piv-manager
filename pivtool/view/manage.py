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

from PySide import QtCore, QtGui
from pivtool import messages as m
from pivtool.view.set_pin_dialog import (SetPinDialog, SetPukDialog,
                                         ResetPinDialog)
from pivtool.view.set_key_dialog import SetKeyDialog
from pivtool.storage import settings, SETTINGS


class ManageDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(ManageDialog, self).__init__(parent)
        self.setWindowTitle(m.manage_pin)
        self.setWindowFlags(self.windowFlags()
                            ^ QtCore.Qt.WindowContextHelpButtonHint)
        self.setFixedSize(480, 180)

        self._controller = controller
        self._build_ui()
        self._controller.on_found(self.refresh)
        self._controller.on_lost(self.accept)
        self._controller.use(self.refresh)

    def showEvent(self, event):
        self.move(self.x() + 15, self.y() + 15)
        event.accept()

    def _build_ui(self):
        # TODO: If PIN is blocked but not PUK blocked, show Reset PIN.
        # TODO: If PIN and PUK are blocked, show RESET DEVICE.
        layout = QtGui.QVBoxLayout(self)

        btns = QtGui.QHBoxLayout()
        self._pin_btn = QtGui.QPushButton(m.change_pin)
        self._pin_btn.clicked.connect(self._controller.wrap(self._change_pin,
                                                            True))
        btns.addWidget(self._pin_btn)

        self._puk_btn = QtGui.QPushButton(m.change_puk)
        self._puk_btn.clicked.connect(self._controller.wrap(self._change_puk,
                                                            True))
        btns.addWidget(self._puk_btn)

        self._key_btn = QtGui.QPushButton(m.change_key)
        self._key_btn.clicked.connect(self._controller.wrap(self._change_key,
                                                            True))
        if not settings.get(SETTINGS.FORCE_PIN_AS_KEY, False):
            btns.addWidget(self._key_btn)
        layout.addLayout(btns)

        self._messages = QtGui.QTextEdit()
        self._messages.setReadOnly(True)
        layout.addWidget(self._messages)

    def refresh(self, controller):
        messages = []
        if controller.pin_blocked:
            messages.append(m.pin_blocked)
        elif controller.does_pin_expire():
            messages.append(m.pin_days_left_1 %
                            controller.get_pin_days_left())
        if controller.pin_is_key:
            messages.append(m.pin_is_key)
        if controller.puk_blocked:
            messages.append(m.puk_blocked)

        if controller.pin_blocked:
            if controller.puk_blocked:
                self._pin_btn.setText(m.reset_device)
            else:
                self._pin_btn.setText(m.reset_pin)
        else:
            self._pin_btn.setText(m.change_pin)

        self._puk_btn.setDisabled(controller.puk_blocked)
        self._messages.setHtml('<br>'.join(messages))

    def _change_pin(self, controller, release):
        if controller.pin_blocked:
            if controller.puk_blocked:
                pass  # TODO: Reset device
                # TODO: Confirm
            else:
                dialog = ResetPinDialog(controller, self)
        else:
            dialog = SetPinDialog(controller, self)
        if dialog.exec_():
            self.refresh(controller)

    def _change_puk(self, controller, release):
        dialog = SetPukDialog(controller, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.puk_changed,
                                          m.puk_changed_desc)
            self.refresh(controller)

    def _change_key(self, controller, release):
        dialog = SetKeyDialog(controller, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.key_changed,
                                          m.key_changed_desc)
            self.refresh(controller)
