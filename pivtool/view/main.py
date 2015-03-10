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
from PySide import QtCore
from pivtool.piv import YkPiv, DeviceGoneError, libversion as ykpiv_version
from pivtool.controller import Controller
from pivtool.storage import get_store, settings, SETTINGS
from pivtool import messages as m, __version__ as version
from pivtool.view.status import StatusWidget
from pivtool.view.init_dialog import InitDialog
from pivtool.view.set_pin_dialog import SetPinDialog
from pivtool.view.settings_dialog import SettingsDialog


ABOUT_TEXT = """
<h2>%s</h2>
%s<br>
%s
<h4>%s</h4>
%%s
<br><br>
""" % (m.app_name, m.copyright, m.version_1, m.libraries)


class NoKeyPresent(QtGui.QWidget):

    def __init__(self):
        super(NoKeyPresent, self).__init__()

        layout = QtGui.QVBoxLayout()
        layout.addWidget(QtGui.QLabel(m.no_key))

        self.setLayout(layout)
        self.startTimer(1500)

    def timerEvent(self, event):
        if QtGui.QApplication.activeWindow() == self.window():
            self.refresh_key()

    def refresh_key(self):
        try:
            window = self.window()
            reader_pattern = settings.get(SETTINGS.CARD_READER)
            controller = Controller(YkPiv(reader=reader_pattern), window)
            if controller.is_uninitialized():
                dialog = InitDialog(controller, self)
                if dialog.exec_():
                    self.refresh_key()
                else:
                    QtCore.QCoreApplication.instance().quit()
            elif controller.is_pin_expired():
                dialog = SetPinDialog(controller, self, True)
                if dialog.exec_():
                    QtGui.QMessageBox.information(self, m.pin_changed,
                                                  m.pin_changed_desc)
                window.setCentralWidget(StatusWidget(controller))
            else:
                window.setCentralWidget(StatusWidget(controller))
        except DeviceGoneError as e:
            print e.message
        except ValueError as e:
            print e.message


class MainWindow(QtGui.QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()

        self._settings = get_store('window')

        self.setMinimumWidth(480)
        self.setMinimumHeight(180)

        self.resize(self._settings.get('size', QtCore.QSize(0, 0)))
        pos = self._settings.get('pos')
        if pos:
            self.move(pos)

        self._build_menu_bar()

    def _build_menu_bar(self):
        file_menu = self.menuBar().addMenu(m.menu_file)
        settings_action = QtGui.QAction(m.action_settings, file_menu)
        settings_action.triggered.connect(self._show_settings)
        file_menu.addAction(settings_action)

        help_menu = self.menuBar().addMenu(m.menu_help)
        about_action = QtGui.QAction(m.action_about, help_menu)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

    def reset(self):
        no_key = NoKeyPresent()
        self.setCentralWidget(no_key)
        no_key.refresh_key()

    def showEvent(self, event):
        self.reset()
        event.accept()

    def closeEvent(self, event):
        self._settings['size'] = self.size()
        self._settings['pos'] = self.pos()
        event.accept()

    def customEvent(self, event):
        event.callback()

    def _libversions(self):
        return 'ykpiv: %s' % ykpiv_version

    def _about(self):
        QtGui.QMessageBox.about(self, m.about_1 % m.app_name, ABOUT_TEXT %
                                (version, self._libversions()))

    def _show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec_()
