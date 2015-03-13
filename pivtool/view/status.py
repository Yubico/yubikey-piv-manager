# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from PySide import QtGui, QtCore
from pivtool import messages as m
from pivtool.piv import DeviceGoneError
from pivtool.storage import settings, SETTINGS
from pivtool.utils import HAS_AD
from pivtool.view.set_pin_dialog import SetPinDialog
from datetime import datetime


class StatusWidget(QtGui.QWidget):

    def __init__(self, controller):
        super(StatusWidget, self).__init__()

        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QFormLayout()

        self._pin = QtGui.QLabel()
        pin_btn = QtGui.QPushButton(m.change_pin)
        pin_btn.clicked.connect(self.change_pin)
        layout.addRow(self._pin, pin_btn)

        self._cert = QtGui.QLabel()
        self._cert_btn = QtGui.QPushButton(m.change_cert)
        self._cert_btn.clicked.connect(self.change_cert)
        layout.addRow(self._cert, self._cert_btn)

        self.setLayout(layout)

        self.startTimer(2500)
        self._refresh()

    def timerEvent(self, event):
        if QtGui.QApplication.activeWindow() == self.window():
            self._refresh()

    def _refresh(self):
        try:
            if self._controller.does_pin_expire():
                self._pin.show()
                if self._controller.is_pin_expired():
                    self._cert_btn.setDisabled(True)
                    self._pin.setStyleSheet("QLabel { color: red; }")
                else:
                    self._cert_btn.setDisabled(not HAS_AD)
                    self._pin.setStyleSheet("")

                pin_days_left = self._controller.get_pin_days_left()
                self._pin.setText(m.pin_days_left_1 % pin_days_left)
            else:
                self._pin.hide()

            cert = self._controller.get_certificate('9a')
            if cert is None or not cert.isValid():
                self._cert.setStyleSheet("QLabel { color: red; }")
            else:
                self._cert.setStyleSheet("")

            if cert is None:
                self._cert.setText(m.cert_not_loaded)
            else:
                expiry = datetime.fromtimestamp(cert.expiryDate().toTime_t())
                self._cert.setText(m.cert_expires_1 % expiry)
        except DeviceGoneError:
            self.parentWidget().window().reset()

    def change_pin(self):
        dialog = SetPinDialog(self._controller, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(self, m.pin_changed,
                                          m.pin_changed_desc)
            self._refresh()

    def change_cert(self):
        res = QtGui.QMessageBox.warning(self, m.change_cert,
                                        m.change_cert_warning,
                                        QtGui.QMessageBox.Ok,
                                        QtGui.QMessageBox.Cancel)
        if res == QtGui.QMessageBox.Ok:
            pin, status = QtGui.QInputDialog.getText(
                self, m.enter_pin, m.pin_label, QtGui.QLineEdit.Password)
            if not status:
                return

            cert_tmpl = settings.get(SETTINGS.CERTREQ_TEMPLATE)
            if cert_tmpl is None:
                # Ask for certificate template
                cert_tmpl, status = QtGui.QInputDialog.getText(
                    self, m.cert_tmpl, m.cert_tmpl)
                if not status:
                    return

            try:
                self._controller.ensure_authenticated()
                worker = QtCore.QCoreApplication.instance().worker
                worker.post(m.changing_cert, (
                    self._controller.request_certificate, pin, cert_tmpl),
                    self._change_cert_callback, True)
            except ValueError as e:
                QtGui.QMessageBox.warning(self, m.error, str(e))

    def _change_cert_callback(self, result):
        if isinstance(result, DeviceGoneError):
            QtGui.QMessageBox.warning(self, m.error, m.device_unplugged)
            self.parentWidget().window().reset()
        elif isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
        else:
            QtGui.QMessageBox.information(self, m.cert_installed,
                                          m.cert_installed_desc)
            self._refresh()
