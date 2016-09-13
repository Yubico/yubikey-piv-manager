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
from pivman import messages as m
from pivman.piv import DeviceGoneError, PivError, KEY_LEN
from pivman.view.set_pin_dialog import SetPinDialog
from pivman.view.utils import KEY_VALIDATOR, pin_field
from pivman.utils import complexity_check
from pivman.storage import settings, SETTINGS
from pivman.yubicommon import qt
from binascii import b2a_hex
import os
import re

NUMERIC_PATTERN = re.compile("^[0-9]+$")


class PinPanel(QtGui.QWidget):

    def __init__(self, headers):
        super(PinPanel, self).__init__()

        self._complex = settings[SETTINGS.COMPLEX_PINS]

        layout = QtGui.QFormLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addRow(headers.section(m.pin))
        self._new_pin = pin_field()
        layout.addRow(m.new_pin_label, self._new_pin)
        self._confirm_pin = pin_field()
        layout.addRow(m.verify_pin_label, self._confirm_pin)
        self._non_numeric_pin_warning = QtGui.QLabel(
            "<p>" + m.non_numeric_pin_warning + "</p>")
        layout.addRow(self._non_numeric_pin_warning)

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

    def __init__(self, headers):
        super(KeyPanel, self).__init__()

        layout = QtGui.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(headers.section(m.management_key))

        self._key_type = QtGui.QButtonGroup(self)
        self._kt_pin = QtGui.QRadioButton(m.use_pin_as_key, self)
        self._kt_key = QtGui.QRadioButton(m.use_separate_key, self)
        self._key_type.addButton(self._kt_pin)
        self._key_type.addButton(self._kt_key)
        self._key_type.buttonClicked.connect(self._change_key_type)
        layout.addWidget(self._kt_pin)
        layout.addWidget(self._kt_key)

        self._adv_panel = AdvancedPanel(headers)

        if settings[SETTINGS.PIN_AS_KEY]:
            self._kt_pin.setChecked(True)
        else:
            self._kt_key.setChecked(True)
            self.layout().addWidget(self._adv_panel)

    def _change_key_type(self, btn):
        if btn == self._kt_pin:
            self.layout().removeWidget(self._adv_panel)
            self._adv_panel.hide()
            self.adjustSize()
            self.parentWidget().adjustSize()
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

    def __init__(self, headers):
        super(AdvancedPanel, self).__init__()

        self._complex = settings[SETTINGS.COMPLEX_PINS]

        layout = QtGui.QFormLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addRow(QtGui.QLabel(m.key_label))
        self._key = QtGui.QLineEdit()
        self._key.setValidator(KEY_VALIDATOR)
        self._key.textChanged.connect(self._validate_key)
        layout.addRow(self._key)

        buttons = QtGui.QDialogButtonBox()
        self._randomize_btn = QtGui.QPushButton(m.randomize)
        self._randomize_btn.clicked.connect(self.randomize)
        self._copy_btn = QtGui.QPushButton(m.copy_clipboard)
        self._copy_btn.clicked.connect(self._copy)
        buttons.addButton(self._randomize_btn,
                          QtGui.QDialogButtonBox.ActionRole)
        buttons.addButton(self._copy_btn, QtGui.QDialogButtonBox.ActionRole)
        layout.addRow(buttons)

        layout.addRow(headers.section(m.puk))
        self._puk = pin_field()
        layout.addRow(m.new_puk_label, self._puk)
        self._confirm_puk = pin_field()
        layout.addRow(m.verify_puk_label, self._confirm_puk)

    def reset(self):
        self.randomize()
        self._puk.setText('')
        self._confirm_puk.setText('')

    def randomize(self):
        self._key.setText(b2a_hex(os.urandom(KEY_LEN)).decode('ascii'))

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
        elif self._complex and not complexity_check(puk):
            error = m.puk_not_complex
        elif puk != self._confirm_puk.text():
            error = m.puk_confirm_mismatch

        if error:
            self._puk.setText('')
            self._confirm_puk.setText('')
            self._puk.setFocus()
            raise ValueError(error)

        return puk


class InitDialog(qt.Dialog):

    def __init__(self, controller, parent=None):
        super(InitDialog, self).__init__(parent)
        self.setWindowTitle(m.initialize)
        self.setMinimumWidth(400)
        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)

        self._pin_panel = PinPanel(self.headers)
        layout.addWidget(self._pin_panel)
        self._key_panel = KeyPanel(self.headers)
        if not settings.is_locked(SETTINGS.PIN_AS_KEY) or \
                not settings[SETTINGS.PIN_AS_KEY]:
            layout.addWidget(self._key_panel)

        layout.addStretch()

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        self._ok_btn = buttons.button(QtGui.QDialogButtonBox.Ok)
        buttons.accepted.connect(self._initialize)
        layout.addWidget(buttons)

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

            if not self._controller.poll():
                self._controller.reconnect()

            self._controller.ensure_authenticated()
            worker = QtCore.QCoreApplication.instance().worker
            worker.post(
                m.initializing,
                (self._controller.initialize, pin, puk, key),
                self._init_callback,
                True
            )
        except DeviceGoneError:
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.close()
        except (PivError, ValueError) as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))

    def _init_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.close()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            if not settings.is_locked(SETTINGS.PIN_AS_KEY):
                settings[SETTINGS.PIN_AS_KEY] = self._key_panel.use_pin
            self.accept()


class MacOSPairingDialog(qt.Dialog):

    def __init__(self, controller, parent=None):
        super(MacOSPairingDialog, self).__init__(parent)
        self.setWindowTitle(m.macos_pairing_title)
        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)
        lbl = QtGui.QLabel(m.macos_pairing_desc)
        lbl.setWordWrap(True)
        layout.addWidget(lbl)
        buttons = QtGui.QDialogButtonBox()
        yes_btn = buttons.addButton(QtGui.QDialogButtonBox.Yes)
        yes_btn.setDefault(True)
        no_btn = buttons.addButton(QtGui.QDialogButtonBox.No)
        no_btn.setAutoDefault(False)
        no_btn.setDefault(False)
        buttons.accepted.connect(self._setup)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)

    def _setup(self):
        try:
            if not self._controller.poll():
                self._controller.reconnect()

            pin = self._controller.ensure_pin()
            if NUMERIC_PATTERN.match(pin):
                self._controller.ensure_authenticated(pin)
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(
                    m.setting_up_macos,
                    (self._controller.setup_for_macos, pin),
                    self.setup_callback,
                    True
                )
            else:
                res = QtGui.QMessageBox.warning(
                    self,
                    m.error,
                    m.non_numeric_pin,
                    QtGui.QMessageBox.Yes,
                    QtGui.QMessageBox.No)

                if res == QtGui.QMessageBox.Yes:
                    SetPinDialog(self._controller, self).exec_()

        except DeviceGoneError:
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.close()
        except Exception as e:
            QtGui.QMessageBox.warning(self, m.error, str(e))

    def setup_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.close()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            self.accept()
            QtGui.QMessageBox.information(
                self, m.setup_macos_compl, m.setup_macos_compl_desc)
