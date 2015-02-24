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
from pivtool.view.status import StatusWidget
from pivtool.view.set_pin_dialog import pin_field
from pivtool.utils import complexity_check


class InitializeWidget(QtGui.QWidget):

    def __init__(self, controller):
        super(InitializeWidget, self).__init__()

        self._controller = controller
        self._build_ui()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.set_pin))

        layout.addWidget(QtGui.QLabel(m.new_pin_label))
        self._new_pin = pin_field()
        layout.addWidget(self._new_pin)
        layout.addWidget(QtGui.QLabel(m.verify_pin_label))
        self._confirm_pin = pin_field()
        layout.addWidget(self._confirm_pin)

        self._new_pin.textChanged.connect(self._check_confirm)
        self._confirm_pin.textChanged.connect(self._check_confirm)

        self._ok_btn = QtGui.QPushButton(m.change_pin)
        self._ok_btn.setAutoDefault(True)
        self._ok_btn.setDisabled(True)
        self._ok_btn.clicked.connect(self._set_pin)
        layout.addWidget(self._ok_btn)
        self.setLayout(layout)

    def _check_confirm(self):
        new_pin = self._new_pin.text()
        if len(new_pin) > 0 and new_pin == self._confirm_pin.text():
            self._ok_btn.setDisabled(False)
        else:
            self._ok_btn.setDisabled(True)

    def _set_pin(self):
        new_pin = self._new_pin.text()

        if not complexity_check(new_pin):
            QtGui.QMessageBox.warning(self, m.pin_not_complex,
                                      m.pin_complexity_desc)
            return

        worker = QtCore.QCoreApplication.instance().worker
        worker.post(m.changing_pin, (self._controller.initialize, new_pin),
                    self._init_callback, True)

    def _init_callback(self, result):
        if isinstance(result, Exception):
            QtGui.QMessageBox.warning(self, m.error, str(result))
            raise result
        else:
            self.parentWidget().setCentralWidget(StatusWidget(self._controller))
