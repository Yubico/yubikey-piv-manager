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

from __future__ import print_function
import sys
import argparse
import signal
import pivman.qt_resources  # noqa: F401
from PySide import QtGui, QtCore
from pivman.view.main import MainWidget
from pivman import __version__ as version, messages as m
from pivman.piv import YkPiv, libversion as ykpiv_version
from pivman.controller import Controller
from pivman.view.set_pin_dialog import SetPinDialog
from pivman.view.settings_dialog import SettingsDialog
from pivman.yubicommon import qt


ABOUT_TEXT = """
<h2>%s</h2>
%s<br>
%s
<h4>%s</h4>
%%s
<br><br>
""" % (m.app_name, m.copyright, m.version_1, m.libraries)


class PivtoolApplication(qt.Application):

    def __init__(self, argv):
        super(PivtoolApplication, self).__init__(m, version)

        QtCore.QCoreApplication.setOrganizationName(m.organization)
        QtCore.QCoreApplication.setOrganizationDomain(m.domain)
        QtCore.QCoreApplication.setApplicationName(m.app_name)

        args = self._parse_args()

        if args.check_only:
            self.check_pin()
            self.quit()
            return

        self.ensure_singleton()

        self._build_menu_bar()
        self._init_window()

    def check_pin(self):
        try:
            controller = Controller(YkPiv())
            if controller.is_uninitialized():
                print('Device not initialized')
            elif controller.is_pin_expired():
                dialog = SetPinDialog(controller, None, True)
                if dialog.exec_():
                    QtGui.QMessageBox.information(None, m.pin_changed,
                                                  m.pin_changed_desc)
        except:
            print('No YubiKey PIV applet detected')

    def _parse_args(self):
        parser = argparse.ArgumentParser(description='YubiKey PIV Manager',
                                         add_help=True)
        parser.add_argument('-c', '--check-only', action='store_true')
        return parser.parse_args()

    def _init_window(self):
        self.window.setWindowTitle(m.win_title_1 % self.version)
        self.window.setWindowIcon(QtGui.QIcon(':/pivman.png'))
        self.window.layout().setSizeConstraint(QtGui.QLayout.SetFixedSize)
        self.window.setCentralWidget(MainWidget())
        self.window.show()
        self.window.raise_()

    def _build_menu_bar(self):
        file_menu = self.window.menuBar().addMenu(m.menu_file)
        settings_action = QtGui.QAction(m.action_settings, file_menu)
        settings_action.triggered.connect(self._show_settings)
        file_menu.addAction(settings_action)

        help_menu = self.window.menuBar().addMenu(m.menu_help)
        about_action = QtGui.QAction(m.action_about, help_menu)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

    def _libversions(self):
        return 'ykpiv: %s' % ykpiv_version

    def _about(self):
        QtGui.QMessageBox.about(
            self.window,
            m.about_1 % m.app_name,
            ABOUT_TEXT % (self.version, self._libversions())
        )

    def _show_settings(self):
        dialog = SettingsDialog(self.window)
        if dialog.exec_():
            self.window.centralWidget().refresh()


def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = PivtoolApplication(sys.argv)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
