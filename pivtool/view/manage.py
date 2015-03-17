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

from PySide import QtGui
from pivtool import messages as m
from pivtool.piv import DeviceGoneError
from pivtool.view.set_pin_dialog import SetPinDialog
from pivtool.view.set_key_dialog import SetKeyDialog
from pivtool.storage import settings, SETTINGS


class ManageDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(ManageDialog, self).__init__(parent)
        self.setWindowTitle(m.manage_pin)
        self.setFixedSize(480, 180)

        self._controller = controller
        self._build_ui()
        self.refresh()

    def showEvent(self, event):
        self.move(self.x() + 15, self.y() + 15)
        event.accept()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)

        btns = QtGui.QHBoxLayout()
        self._pin_btn = QtGui.QPushButton(m.change_pin)
        self._pin_btn.clicked.connect(self._change_pin)
        btns.addWidget(self._pin_btn)
        self._puk_btn = QtGui.QPushButton(m.change_puk)
        self._puk_btn.clicked.connect(self._change_puk)
        btns.addWidget(self._puk_btn)
        self._key_btn = QtGui.QPushButton(m.change_key)
        self._key_btn.clicked.connect(self._change_key)
        btns.addWidget(self._key_btn)
        layout.addLayout(btns)

        self._messages = QtGui.QTextEdit()
        self._messages.setReadOnly(True)
        layout.addWidget(self._messages)

    def refresh(self):
        messages = []
        if self._controller.does_pin_expire():
            messages.append(m.pin_days_left_1 %
                            self._controller.get_pin_days_left())
        if self._controller.pin_is_key:
            messages.append(m.pin_is_key)
        self._messages.setHtml('<br>'.join(messages))

    def _change_pin(self):
        dialog = SetPinDialog(self._controller, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.pin_changed,
                                          m.pin_changed_desc)
            self.refresh()

    def _change_puk(self):
        dialog = SetPinDialog(self._controller, self, puk=True)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.puk_changed,
                                          m.puk_changed_desc)
            self.refresh()

    def _change_key(self):
        dialog = SetKeyDialog(self._controller, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.key_changed,
                                          m.key_changed_desc)
            self.refresh()
