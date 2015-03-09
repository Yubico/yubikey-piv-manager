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
from PySide import QtCore
from collections import MutableMapping

__all__ = [
    'CONFIG_HOME',
    'Settings',
]

CONFIG_HOME = os.path.join(os.path.expanduser('~'), '.pivtool')

_settings = QtCore.QSettings(os.path.join(CONFIG_HOME, 'settings.ini'),
                             QtCore.QSettings.IniFormat)


class SettingsLock(QtCore.QMutex):
    def __init__(self):
        super(SettingsLock, self).__init__(QtCore.QMutex.Recursive)
        self._in_group = False

    def with_lock(self, func):
        def wrapped_f(caller, *args, **kwargs):
            try:
                self.lock()
                group = caller._group
                if not self._in_group and group is not None:
                    try:
                        self._in_group = True
                        _settings.beginGroup(group)
                        return func(caller, *args, **kwargs)
                    finally:
                        _settings.endGroup()
                        self._in_group = False
                return func(caller, *args, **kwargs)
            finally:
                self.unlock()
        return wrapped_f


_lock = SettingsLock()


class Settings(MutableMapping):

    def __init__(self, group=None):
        super(Settings, self).__init__()
        self._group = group

    @_lock.with_lock
    def get(self, key, default=None):
        return _settings.value(key, default)

    def __getitem__(self, key):
        return self.get(key)

    @_lock.with_lock
    def __setitem__(self, key, value):
        _settings.setValue(key, value)

    @_lock.with_lock
    def __delitem__(self, key):
        _settings.remove(key)

    @_lock.with_lock
    def __iter__(self):
        return self.keys().__iter__()

    @_lock.with_lock
    def __len__(self):
        return len(_settings.childKeys())

    @_lock.with_lock
    def __contains__(self, key):
        return _settings.contains(key)

    @_lock.with_lock
    def keys(self):
        return _settings.childKeys()

    @_lock.with_lock
    def update(self, data):
        for key, value in data.items():
            self[key] = value

    def clear(self):
        _settings.remove(self._group)

    def rename(self, new_name):
        data = dict(self)
        self.clear()

        self._group = new_name
        self.update(data)

    def __repr__(self):
        return 'Settings(%s): %s' % (self._group, dict(self))
