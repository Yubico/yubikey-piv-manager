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
from pivman import messages as m
from pivman.storage import settings, SETTINGS
from pivman.yubicommon import qt


class UsagePolicyDialog(qt.Dialog):

    def __init__(self, controller, slot, parent=None):
        super(UsagePolicyDialog, self).__init__(parent)

        self._controller = controller
        self._slot = slot
        self.has_content = False
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle(m.usage_policy)
        self.setFixedWidth(400)

        layout = QtGui.QVBoxLayout(self)

        self._build_usage_policy(layout)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_usage_policy(self, layout):
        self._pin_policy = QtGui.QComboBox()
        self._pin_policy.addItem(m.pin_policy_default, None)
        self._pin_policy.addItem(m.pin_policy_never, 'never')
        self._pin_policy.addItem(m.pin_policy_once, 'once')
        self._pin_policy.addItem(m.pin_policy_always, 'always')

        self._touch_policy = QtGui.QCheckBox(m.touch_policy)
        if self._controller.version_tuple < (4, 0, 0):
            return

        use_pin_policy = self._slot in settings[SETTINGS.PIN_POLICY_SLOTS]
        use_touch_policy = self._slot in settings[SETTINGS.TOUCH_POLICY_SLOTS]

        if use_pin_policy or use_touch_policy:
            self.has_content = True
            layout.addWidget(self.section(m.usage_policy))

        if use_pin_policy:
            pin_policy = settings[SETTINGS.PIN_POLICY]
            for index in range(self._pin_policy.count()):
                if self._pin_policy.itemData(index) == pin_policy:
                    pin_policy_text = self._pin_policy.itemText(index)
                    self._pin_policy.setCurrentIndex(index)
                    break
            else:
                pin_policy = None
                pin_policy_text = m.pin_policy_default

            if settings.is_locked(SETTINGS.PIN_POLICY):
                layout.addWidget(QtGui.QLabel(m.pin_policy_1 % pin_policy_text))
            else:
                pin_policy_box = QtGui.QHBoxLayout()
                pin_policy_box.addWidget(QtGui.QLabel(m.pin_policy))
                pin_policy_box.addWidget(self._pin_policy)
                layout.addLayout(pin_policy_box)

        if use_touch_policy:
            self._touch_policy.setChecked(settings[SETTINGS.TOUCH_POLICY])
            self._touch_policy.setDisabled(
                settings.is_locked(SETTINGS.TOUCH_POLICY))
            layout.addWidget(self._touch_policy)

    @property
    def pin_policy(self):
        if settings.is_locked(SETTINGS.PIN_POLICY):
            return settings[SETTINGS.PIN_POLICY]
        return self._pin_policy.itemData(self._pin_policy.currentIndex())

    @property
    def touch_policy(self):
        if self._controller.version_tuple < (4, 0, 0):
            return False
        if settings.is_locked(SETTINGS.TOUCH_POLICY):
            return settings[SETTINGS.TOUCH_POLICY]
        return self._touch_policy.isChecked()
