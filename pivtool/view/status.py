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

from PySide import QtGui
from pivtool import messages as m
from pivtool.view.set_pin_dialog import SetPinDialog
from datetime import datetime, timedelta


class StatusWidget(QtGui.QWidget):

    def __init__(self, key):
        super(StatusWidget, self).__init__()

        self._key = key
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()

        name_row = QtGui.QHBoxLayout()
        self._name = QtGui.QLabel()
        name_row.addWidget(self._name, 3)
        name_btn = QtGui.QPushButton(m.change_name)
        name_btn.clicked.connect(self.change_name)
        name_row.addWidget(name_btn, 2)
        layout.addLayout(name_row)

        pin_row = QtGui.QHBoxLayout()
        self._pin = QtGui.QLabel()
        pin_row.addWidget(self._pin, 3)
        pin_btn = QtGui.QPushButton(m.change_pin)
        pin_btn.clicked.connect(self.change_pin)
        pin_row.addWidget(pin_btn, 2)
        layout.addLayout(pin_row)

        cert_row = QtGui.QHBoxLayout()
        self._cert = QtGui.QLabel()
        cert_row.addWidget(self._cert, 3)
        cert_btn = QtGui.QPushButton(m.change_cert)
        cert_btn.clicked.connect(self.change_cert)
        cert_row.addWidget(cert_btn, 2)
        layout.addLayout(cert_row)

        layout.addStretch()
        self.setLayout(layout)

        self._refresh()

    def _refresh(self):
        self._name.setText(m.name_1 % self._key.name)

        last_changed = self._key.pin_last_changed
        self._pin.setStyleSheet("QLabel { color: red; }")
        if last_changed is not None:
            last_changed = datetime.fromtimestamp(last_changed)
            if datetime.now() - last_changed < timedelta(days=30):
                self._pin.setStyleSheet("")
        else:
            last_changed = m.unknown
        self._pin.setText(m.pin_last_changed_1 % last_changed)

        # TODO: Find expiration of certificate
        self._cert.setText(m.cert_expires_1 % m.unknown)

    def change_name(self):
        name, ok = QtGui.QInputDialog.getText(
            self, m.name, m.change_name_desc, text=self._key.name)
        if ok:
            self._key.name = name
            self._refresh()

    def change_pin(self):
        dialog = SetPinDialog(self._key, self)
        if dialog.exec_():
            QtGui.QMessageBox.information(
                self, "PIN Changed",
                "The PIN has been successfully changed.")
            self._refresh()

    def change_cert(self):
        print "TODO"
