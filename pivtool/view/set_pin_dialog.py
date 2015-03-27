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
from pivtool.piv import WrongPinError
from pivtool.storage import settings, SETTINGS
from pivtool.utils import complexity_check
from pivtool.view.utils import pin_field


class SetPinDialog(QtGui.QDialog):
    window_title = m.change_pin
    label_current = m.current_pin_label
    label_new = m.new_pin_label
    label_new_complex = m.new_complex_pin_label
    label_verify = m.verify_pin_label
    warn_not_changed = m.pin_not_changed
    desc_not_changed = m.pin_not_changed_desc
    warn_not_complex = m.pin_not_complex
    busy = m.changing_pin
    info_changed = m.pin_changed
    desc_changed = m.pin_changed_desc

    def __init__(self, controller, parent=None, forced=False):
        super(SetPinDialog, self).__init__(parent)

        self._complex = settings.get(SETTINGS.COMPLEX_PINS, False)
        self._controller = controller
        self._build_ui(forced)

    def _build_ui(self, forced):
        self.setWindowFlags(self.windowFlags()
                            ^ QtCore.Qt.WindowContextHelpButtonHint)
        self.setWindowTitle(self.window_title)

        layout = QtGui.QVBoxLayout(self)
        if forced:
            layout.addWidget(QtGui.QLabel(m.change_pin_forced_desc))

        layout.addWidget(QtGui.QLabel(self.label_current))
        self._old_pin = pin_field()
        layout.addWidget(self._old_pin)
        layout.addWidget(QtGui.QLabel(self.label_new_complex
                                      if self._complex else self.label_new))
        self._new_pin = pin_field()
        layout.addWidget(self._new_pin)
        layout.addWidget(QtGui.QLabel(self.label_verify))
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

    def _prepare_fn(self, old_pin, new_pin):
        self._controller.verify_pin(old_pin)
        if self._controller.does_pin_expire():
            self._controller.ensure_authenticated(old_pin)
        return (self._controller.change_pin, old_pin, new_pin)

    def _set_pin(self):
        old_pin = self._old_pin.text()
        new_pin = self._new_pin.text()

        if old_pin == new_pin:
            self._invalid_pin(self.warn_not_changed, self.desc_not_changed)
        elif self._complex and not complexity_check(new_pin):
            self._invalid_pin(self.warn_not_complex, m.pin_complexity_desc)
        else:
            try:
                fn = self._prepare_fn(old_pin, new_pin)
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(self.busy, fn, self._change_pin_callback, True)
            except Exception as e:
                self._change_pin_callback(e)

    def _change_pin_callback(self, result):
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
            if isinstance(result, WrongPinError):
                self._old_pin.setText('')
                self._old_pin.setFocus()
                if result.blocked:
                    self.accept()
            else:
                self.reject()
        else:
            self.accept()
            QtGui.QMessageBox.information(self, self.info_changed,
                                          self.desc_changed)


class SetPukDialog(SetPinDialog):
    window_title = m.change_puk
    label_current = m.current_puk_label
    label_new = m.new_puk_label
    label_new_complex = m.new_complex_puk_label
    label_verify = m.verify_puk_label
    warn_not_changed = m.puk_not_changed
    desc_not_changed = m.puk_not_changed_desc
    warn_not_complex = m.puk_not_complex
    busy = m.changing_puk
    info_changed = m.pin_changed
    desc_changed = m.pin_changed_desc

    def _prepare_fn(self, old_puk, new_puk):
        return (self._controller.change_puk, old_puk, new_puk)


class ResetPinDialog(SetPinDialog):
    window_title = m.reset_pin
    label_current = m.puk_label
    label_new = m.new_pin_label
    label_new_complex = m.new_complex_pin_label
    label_verify = m.verify_pin_label
    warn_not_changed = m.pin_puk_same
    desc_not_changed = m.pin_puk_same_desc
    warn_not_complex = m.pin_not_complex
    busy = m.changing_pin
    info_changed = m.pin_changed
    desc_changed = m.pin_changed_desc

    def _prepare_fn(self, puk, new_pin):
        return (self._controller.reset_pin, puk, new_pin)
