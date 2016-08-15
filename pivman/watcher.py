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
from PySide import QtGui, QtCore
from pivman.controller import Controller
from pivman.piv import YkPiv, PivError, DeviceGoneError
from pivman.storage import settings, SETTINGS
from functools import partial
from Queue import Queue


class Release(object):

    def __init__(self, fn):
        self._fn = fn

    def __del__(self):
        self._fn()

    def __call__(self):
        raise Exception('EXPLICIT CALL')
        self._fn()
        self._fn = lambda: None


class ControllerWatcher(QtCore.QObject):
    _device_found = QtCore.Signal()
    _device_lost = QtCore.Signal()

    def __init__(self):
        super(ControllerWatcher, self).__init__()

        self._waiters = Queue()
        self._controller = None

        self._lock = QtCore.QMutex()
        self._lock.lock()
        self._worker = QtCore.QCoreApplication.instance().worker
        self._worker.post_bg(self._poll, self._release, True)

        self.startTimer(2000)

    def timerEvent(self, event):
        if QtGui.QApplication.activeWindow() and self._lock.tryLock():
            self._worker.post_bg(self._poll, self._release, True)
        event.accept()

    def _release(self, result=None):
        if self._controller and not self._waiters.empty():
            waiter = self._waiters.get_nowait()
            waiter(self._controller, Release(self._release))
        else:
            self._lock.unlock()

    def _poll(self):
        reader = settings[SETTINGS.CARD_READER]
        if self._controller:
            if self._controller.poll():
                return
            self._controller = None
            self._device_lost.emit()

        try:
            self._controller = Controller(YkPiv(reader=reader))
            self._device_found.emit()
        except (PivError, DeviceGoneError) as e:
            print(e)

    def on_found(self, fn, hold_lock=False):
        self._device_found.connect(self.wrap(fn, hold_lock))

    def on_lost(self, fn):
        self._device_lost.connect(fn)

    def use(self, fn, hold_lock=False):
        if not hold_lock:
            def waiter(controller, release):
                fn(controller)
        else:
            waiter = fn

        if self._controller and self._lock.tryLock():
            waiter(self._controller, Release(self._release))
        else:
            self._waiters.put(waiter)

    def wrap(self, fn, hold_lock=False):
        return partial(self.use, fn, hold_lock)
