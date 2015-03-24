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

TOP_SECTION = "<b>%s</b>"
SECTION = "<br><b>%s</b>"

PIN_VALIDATOR = QtGui.QRegExpValidator(QtCore.QRegExp(r'.{6,8}'))
KEY_VALIDATOR = QtGui.QRegExpValidator(QtCore.QRegExp(r'[0-9a-fA-F]{48}'))


def pin_field():
    field = QtGui.QLineEdit()
    field.setEchoMode(QtGui.QLineEdit.Password)
    field.setMaxLength(8)
    field.setValidator(PIN_VALIDATOR)
    return field


def get_active_window():
    active_win = QtGui.QApplication.activeWindow()
    if active_win is not None:
        return active_win

    wins = filter(lambda w: isinstance(w, QtGui.QDialog) and w.isVisible(),
                  QtGui.QApplication.topLevelWidgets())

    if not wins:
        return QtCore.QCoreApplication.instance().window

    return wins[0]  # TODO: If more than one candidates remain, find best one.
