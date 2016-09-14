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
from PySide import QtCore
from pivman import messages as m
from pivman.utils import is_macos_sierra_or_later
from pivman.piv import YkPiv
from pivman.storage import settings, SETTINGS
from pivman.controller import Controller
from pivman.view.utils import IMPORTANT
from pivman.view.init_dialog import InitDialog, MacOSPairingDialog
from pivman.view.set_pin_dialog import SetPinDialog
from pivman.view.manage import ManageDialog
from pivman.view.cert import CertDialog


class MainWidget(QtGui.QWidget):
    def __init__(self):
        super(MainWidget, self).__init__()

        self._lock = QtCore.QMutex()
        self._build_ui()
        self.refresh()

        self._t = self.startTimer(2000)

    @property
    def _controller(self):
        try:
            return Controller(YkPiv(reader=settings[SETTINGS.CARD_READER]))
        except:
            return None

    def showEvent(self, event):
        self.refresh()
        event.accept()

    def timerEvent(self, event):
        if QtGui.QApplication.activeWindow() == self.window():
            self.refresh()
        event.accept()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)

        btns = QtGui.QHBoxLayout()
        self._cert_btn = QtGui.QPushButton(m.certificates)
        self._cert_btn.clicked.connect(self._manage_certs)
        btns.addWidget(self._cert_btn)
        self._pin_btn = QtGui.QPushButton(m.manage_pin)
        self._pin_btn.clicked.connect(self._manage_pin)
        btns.addWidget(self._pin_btn)
        self._setup_macos_btn = QtGui.QPushButton(m.setup_for_macos)
        if is_macos_sierra_or_later():
            self._setup_macos_btn.clicked.connect(self._setup_for_macos)
            btns.addWidget(self._setup_macos_btn)
        layout.addLayout(btns)

        self._messages = QtGui.QTextEdit()
        self._messages.setFixedSize(480, 100)
        self._messages.setReadOnly(True)
        layout.addWidget(self._messages)

    def _manage_pin(self):
        self.killTimer(self._t)
        try:
            ManageDialog(self._controller, self).exec_()
        finally:
            self._t = self.startTimer(2000)
        # self.refresh()

    def _manage_certs(self):
        self.killTimer(self._t)
        try:
            CertDialog(self._controller, self).exec_()
        finally:
            self._t = self.startTimer(2000)
        # self.refresh()

    def _setup_for_macos(self):
        self.killTimer(self._t)
        try:
            MacOSPairingDialog(self._controller, self).exec_()
        finally:
            self._t = self.startTimer(2000)
        # self.refresh()

    def refresh(self):
        self._refresh_controller(self._controller)

    def _no_controller(self):
        self._pin_btn.setEnabled(False)
        self._cert_btn.setEnabled(False)
        self._setup_macos_btn.setEnabled(False)
        self._messages.setHtml(m.no_key)

    def _refresh_controller(self, controller):
        if not controller:
            self._no_controller()
            return

        self._pin_btn.setEnabled(True)
        self._cert_btn.setDisabled(controller.pin_blocked)
        self._setup_macos_btn.setDisabled(controller.pin_blocked)

        messages = []
        if controller.pin_blocked:
            messages.append(IMPORTANT % m.pin_blocked)
        messages.append(m.key_with_applet_1
                        % controller.version.decode('ascii'))
        n_certs = len(controller.certs)
        messages.append(m.certs_loaded_1 % n_certs or m.no)

        self._messages.setHtml('<br>'.join(messages))

        if controller.is_uninitialized():
            dialog = InitDialog(controller, self)
            if dialog.exec_():
                if controller.should_show_macos_dialog():
                    self._setup_for_macos(controller)
                else:
                    self.refresh()
            else:
                QtCore.QCoreApplication.instance().quit()
        elif controller.is_pin_expired() and not controller.pin_blocked:
            dialog = SetPinDialog(controller, self, True)
            if dialog.exec_():
                self.refresh()
            else:
                QtCore.QCoreApplication.instance().quit()
