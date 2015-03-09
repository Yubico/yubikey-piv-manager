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
from pivtool import messages as m
from PySide import QtCore
from collections import MutableMapping

__all__ = [
    'CONFIG_HOME',
    'get_settings',
]

CONFIG_HOME = os.path.join(os.path.expanduser('~'), '.pivtool')
_settings = QtCore.QSettings(os.path.join(CONFIG_HOME, 'settings.ini'),
                             QtCore.QSettings.IniFormat)
_mutex = QtCore.QMutex(QtCore.QMutex.Recursive)


def get_settings(group):
    settings_group = SettingsGroup(_settings, _mutex, group)
    if group == 'settings':
        master = QtCore.QSettings(m.organization, m.app_name)
        return PySettings(SettingsOverlay(master, settings_group))
    return PySettings(settings_group)


class SettingsGroup(object):
    def __init__(self, settings, mutex, group):
        self._settings = settings
        self._mutex = mutex
        self._group = group

    def __getattr__(self, method_name):
        if hasattr(self._settings, method_name):
            fn = getattr(self._settings, method_name)

            def wrapped(*args, **kwargs):
                try:
                    self._mutex.lock()
                    self._settings.beginGroup(self._group)
                    return fn(*args, **kwargs)
                finally:
                    self._settings.endGroup()
                    self._mutex.unlock()
            return wrapped

    def rename(self, new_name):
        data = dict((key, self.value(key)) for key in self.childKeys())
        self.remove('')
        self._group = new_name
        for k, v in data.items():
            self.setValue(k, v)

    def __repr__(self):
        return 'Group(%s)' % self._group


class SettingsOverlay(object):
    def __init__(self, master, overlay):
        self._master = master
        self._overlay = overlay

    def __getattr__(self, method_name):
        return getattr(self._overlay, method_name)

    def rename(self, new_name):
        raise NotImplementedError()

    def value(self, key, default=None):
        """Give preference to master"""
        return self._master.value(key, self._overlay.value(key, default))

    def childKeys(self):
        """Combine keys of master and overlay"""
        return list(set(self._master.childKeys() + self._overlay.childKeys()))

    def __repr__(self):
        return 'Overlay(%s)' % self._group


class PySettings(MutableMapping):

    def __init__(self, settings):
        self._settings = settings

    def __getattr__(self, method_name):
        return getattr(self._settings, method_name)

    def get(self, key, default=None):
        return self._settings.value(key, default)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self._settings.setValue(key, value)

    def __delitem__(self, key):
        self._settings.remove(key)

    def __iter__(self):
        for key in self.keys():
            yield key

    def __len__(self):
        return len(self._settings.childKeys())

    def __contains__(self, key):
        return self._settings.contains(key)

    def keys(self):
        return self._settings.childKeys()

    def update(self, data):
        for key, value in data.items():
            self[key] = value

    def clear(self):
        self._settings.remove('')

    def __repr__(self):
        return 'Settings(%s): %s' % (self._settings, dict(self))
