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
from pivtool.utils import complexity_check


class SettingsDialog(QtGui.QDialog):

    def __init__(self, parent=None):
        super(SettingsDialog, self).__init__(parent)

        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.settings))

        layout.addWidget(QtGui.QLabel(m.reader_name))
        self._reader_pattern = QtGui.QLineEdit()
        layout.addWidget(self._reader_pattern)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def _save(self):
            self.accept()

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

        if old_pin == new_pin:
            self._invalid_pin(m.pin_not_changed, m.pin_not_changed_desc)
        elif not complexity_check(new_pin):
            self._invalid_pin(m.pin_not_complex, m.pin_complexity_desc)
        else:
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(m.changing_pin,
                        (self._controller.change_pin, old_pin, new_pin),
                        self._change_pin_callback, True)

    def _change_pin_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.parentWidget().window().reset()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
            self._old_pin.setText('')
            self._old_pin.setFocus()
        else:
            self.accept()
