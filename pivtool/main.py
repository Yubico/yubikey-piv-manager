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

import os
import sys
import time
import argparse
import pivtool.qt_resources
from PySide import QtGui, QtCore
from pivtool.view.main import MainWindow
from pivtool.worker import Worker
from pivtool import __version__ as version, messages as m
from pivtool.piv import YkPiv
from pivtool.controller import Controller
from pivtool.view.set_pin_dialog import SetPinDialog

if getattr(sys, 'frozen', False):
    # we are running in a PyInstaller bundle
    basedir = sys._MEIPASS
else:
    # we are running in a normal Python environment
    basedir = os.path.dirname(__file__)

# Font fixes for OSX
if sys.platform == 'darwin':
    from platform import mac_ver
    mac_version = tuple(mac_ver()[0].split('.'))
    if (10, 9) <= mac_version < (10, 10):  # Mavericks
        QtGui.QFont.insertSubstitution(".Lucida Grande UI", "Lucida Grande")
    if (10, 10) <= mac_version:  # Yosemite
        QtGui.QFont.insertSubstitution(".Helvetica Neue DeskInterface", "Helvetica Neue")


class PivtoolApplication(QtGui.QApplication):

    def __init__(self, argv):
        super(PivtoolApplication, self).__init__(argv)

        self._set_basedir()

        m._translate(self)

        QtCore.QCoreApplication.setOrganizationName(m.organization)
        QtCore.QCoreApplication.setOrganizationDomain(m.domain)
        QtCore.QCoreApplication.setApplicationName(m.app_name)

        self.window = self._create_window()
        self.worker = Worker(self.window)

        QtCore.QTimer.singleShot(0, self.start)

    def start(self):
        args = self._parse_args()

        if args.check_only:
            self.check_pin()
            self.quit()
            return

        self.window.show()
        self.window.raise_()

    def check_pin(self):
        try:
            controller = Controller(YkPiv())
            if controller.is_pin_expired():
                dialog = SetPinDialog(controller, None, True)
                if dialog.exec_():
                    QtGui.QMessageBox.information(None, m.pin_changed,
                                                    m.pin_changed_desc)
        except:
            print "No YubiKey PIV applet detected"

    def _parse_args(self):
        parser = argparse.ArgumentParser(description="Yubico PIV tool",
                                         add_help=True)
        parser.add_argument('-c', '--check-only', action='store_true')
        return parser.parse_args()

    def _set_basedir(self):
        if getattr(sys, 'frozen', False):
            # we are running in a PyInstaller bundle
            self.basedir = sys._MEIPASS
        else:
            # we are running in a normal Python environment
            self.basedir = os.path.dirname(__file__)

    def _create_window(self):
        window = MainWindow()
        window.setWindowTitle(m.win_title_1 % version)
        window.setWindowIcon(QtGui.QIcon(':/pivtool.png'))
        return window


def main():
    app = PivtoolApplication(sys.argv)
    status = app.exec_()
    app.worker.thread().quit()
    app.deleteLater()
    time.sleep(0.01) # Without this the process sometimes stalls.
    sys.exit(status)
