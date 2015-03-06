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
from pivtool.view.utils import HEADER, KEY_VALIDATOR, pin_field
from pivtool.utils import complexity_check
import os


class PinPanel(QtGui.QWidget):

    def __init__(self, enforce_complexity):
        super(PinPanel, self).__init__()

        self._complex = enforce_complexity
        # TODO: Change labels when not complex

        layout = QtGui.QFormLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addRow(QtGui.QLabel(HEADER % m.pin))
        self._new_pin = pin_field()
        layout.addRow(m.new_pin_label, self._new_pin)
        self._confirm_pin = pin_field()
        layout.addRow(m.verify_pin_label, self._confirm_pin)
        self.setLayout(layout)

    @property
    def pin(self):
        error = None

        new_pin = self._new_pin.text()
        if not new_pin:
            error = m.pin_empty
        elif new_pin != self._confirm_pin.text():
            error = m.pin_confirm_mismatch
        elif self._complex and not complexity_check(new_pin):
            error = m.pin_complexity_desc

        if error:
            self._new_pin.setText('')
            self._confirm_pin.setText('')
            self._new_pin.setFocus()
            raise ValueError(error)

        return new_pin


class KeyPanel(QtGui.QWidget):

    def __init__(self):
        super(KeyPanel, self).__init__()

        layout = QtGui.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QtGui.QLabel(HEADER % m.management_key))

        self._key_type = QtGui.QButtonGroup(self)
        self._kt_pin = QtGui.QRadioButton("PIN is key", self)
        self._kt_pin.setChecked(True)
        self._kt_key = QtGui.QRadioButton("Use a separate key", self)
        self._key_type.addButton(self._kt_pin)
        self._key_type.addButton(self._kt_key)
        self._key_type.buttonClicked.connect(self._change_key_type)
        layout.addWidget(self._kt_pin)
        layout.addWidget(self._kt_key)

        self.setLayout(layout)

        self._adv_panel = AdvancedPanel()

    def _change_key_type(self, btn):
        if btn == self._kt_pin:
            self.layout().removeWidget(self._adv_panel)
            self._adv_panel.hide()
            widget = self
            while widget:
                widget.adjustSize()
                widget = widget.parentWidget()
        else:
            self._adv_panel.reset()
            self.layout().addWidget(self._adv_panel)
            self._adv_panel.show()

    @property
    def use_pin(self):
        return self._key_type.checkedButton() == self._kt_pin

    @property
    def puk(self):
        return self._adv_panel.puk if not self.use_pin else None

    @property
    def key(self):
        return self._adv_panel.key if not self.use_pin else None


class AdvancedPanel(QtGui.QWidget):

    def __init__(self):
        super(AdvancedPanel, self).__init__()

        layout = QtGui.QFormLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addRow(QtGui.QLabel(m.key_label))
        self._key = QtGui.QLineEdit()
        self._key.setValidator(KEY_VALIDATOR)
        self._key.textChanged.connect(self._validate_key)
        layout.addRow(self._key)

        buttons = QtGui.QDialogButtonBox()
        self._randomize_btn = QtGui.QPushButton("Randomize")
        self._randomize_btn.clicked.connect(self.randomize)
        self._copy_btn = QtGui.QPushButton("Copy to clipboard")
        self._copy_btn.clicked.connect(self._copy)
        buttons.addButton(self._randomize_btn,
                          QtGui.QDialogButtonBox.ActionRole)
        buttons.addButton(self._copy_btn, QtGui.QDialogButtonBox.ActionRole)
        layout.addRow(buttons)

        layout.addRow(QtGui.QLabel(HEADER % m.puk))
        self._puk = pin_field()
        layout.addRow(m.new_puk_label, self._puk)
        self._confirm_puk = pin_field()
        layout.addRow(m.verify_pin_label, self._confirm_puk)

        self.setLayout(layout)

    def reset(self):
        self.randomize()
        self._puk.setText('')
        self._confirm_puk.setText('')

    def randomize(self):
        self._key.setText(os.urandom(KEY_LEN).encode('hex'))

    def _validate_key(self):
        self._copy_btn.setDisabled(not self._key.hasAcceptableInput())

    def _copy(self):
        self._key.selectAll()
        self._key.copy()
        self._key.deselect()

    @property
    def key(self):
        if not self._key.hasAcceptableInput():
            self._key.setText('')
            self._key.setFocus()
            raise ValueError(m.key_invalid_desc)

        return self._key.text()

    @property
    def puk(self):
        error = None

        puk = self._puk.text()
        if not puk:
            return None
        elif puk != self._confirm_puk.text():
            error = m.puk_confirm_mismatch

        if error:
            self._puk.setText('')
            self._confirm_puk.setText('')
            self._puk.setFocus()
            raise ValueError(error)

        return puk


class InitDialog(QtGui.QDialog):

    def __init__(self, controller, parent=None):
        super(InitDialog, self).__init__(parent)

        self._controller = controller
        self.setMinimumWidth(400)
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.initialize))

        self._pin_panel = PinPanel(True)
        layout.addWidget(self._pin_panel)
        self._key_panel = KeyPanel()
        if True:  # TODO: If policy mandates PIN as key, don't show key panel
            layout.addWidget(self._key_panel)
        layout.addStretch()

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        buttons.accepted.connect(self._initialize)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def _initialize(self):
        try:
            pin = self._pin_panel.pin
            key = self._key_panel.key
            puk = self._key_panel.puk

            if key is not None and puk is None:
                res = QtGui.QMessageBox.warning(self, m.no_puk,
                                                m.no_puk_warning,
                                                QtGui.QMessageBox.Ok,
                                                QtGui.QMessageBox.Cancel)
                if res != QtGui.QMessageBox.Ok:
                    return


            self._controller.ensure_authenticated()
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(
                m.initializing,
                (self._controller.initialize, pin, puk, key),
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
