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
from pivtool.piv import DeviceGoneError, PivError
from pivtool.storage import settings, SETTINGS
from pivtool.utils import complexity_check
from pivtool.view.utils import pin_field


class SetPinDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None, forced=False, puk=False):
        super(SetPinDialog, self).__init__(parent)

        self._puk = puk
        self._complex = settings.get(SETTINGS.COMPLEX_PINS, False)
        self._controller = controller
        self._build_ui(forced, not puk)

    def _build_ui(self, forced, pin):
        self.setWindowTitle(m.change_pin if pin else m.change_puk)

        layout = QtGui.QVBoxLayout(self)
        if forced:
            label = m.change_pin_forced_desc \
                if pin else m.change_puk_forced_desc
            layout.addWidget(QtGui.QLabel(label))

        layout.addWidget(QtGui.QLabel(m.current_pin_label
                                      if pin else m.current_puk_label))
        self._old_pin = pin_field()
        layout.addWidget(self._old_pin)
        if self._complex:
            label = m.new_complex_pin_label if pin else m.new_complex_puk_label
        else:
            label = m.new_pin_label if pin else m.new_puk_label
        layout.addWidget(QtGui.QLabel(label))
        self._new_pin = pin_field()
        layout.addWidget(self._new_pin)
        layout.addWidget(QtGui.QLabel(m.verify_pin_label
                                      if pin else m.verify_puk_label))
        self._confirm_pin = pin_field()
        layout.addWidget(self._confirm_pin)

        self._new_pin.textChanged.connect(self._check_confirm)
        self._confirm_pin.textChanged.connect(self._check_confirm)

        if forced:
            buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        else:
            buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                             QtGui.QDialogButtonBox.Cancel)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        self._ok_btn.setDisabled(True)
        buttons.accepted.connect(self._set_pin)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _check_confirm(self):
        new_pin = self._new_pin.text()
        if len(new_pin) > 0 and new_pin == self._confirm_pin.text():
            self._ok_btn.setDisabled(False)
        else:
            self._ok_btn.setDisabled(True)

    def _invalid_pin(self, title, reason):
        QtGui.QMessageBox.warning(self, title, reason)
        self._new_pin.setText('')
        self._confirm_pin.setText('')
        self._new_pin.setFocus()

    def _set_pin(self):
        old_pin = self._old_pin.text()
        new_pin = self._new_pin.text()

        pin = not self._puk

        if old_pin == new_pin:
            if pin:
                self._invalid_pin(m.pin_not_changed, m.pin_not_changed_desc)
            else:
                self._invalid_pin(m.puk_not_changed, m.puk_not_changed_desc)
        elif self._complex and not complexity_check(new_pin):
            if pin:
                self._invalid_pin(m.pin_not_complex, m.pin_complexity_desc)
            else:
                self._invalid_pin(m.puk_not_complex, m.puk_complexity_desc)
        else:
            try:
                if pin:
                    self._controller.ensure_authenticated(old_pin)
                fn = self._controller.change_pin \
                    if pin else self._controller.change_puk
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(m.changing_pin if pin else m.changing_puk,
                            (fn, old_pin, new_pin),
                            self._change_pin_callback, True)
            except ValueError as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))
            except (DeviceGoneError, PivError) as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))
                self.reject()

    def _change_pin_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.reject()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
            self._old_pin.setText('')
            self._old_pin.setFocus()
        else:
            self.accept()
