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
from pivtool.piv import CERT_SLOTS
from PySide import QtCore
from collections import MutableMapping, namedtuple
from getpass import getuser
from sys import platform

__all__ = [
    'CONFIG_HOME',
    'SETTINGS',
    'get_store',
    'settings'
]

CONFIG_HOME = os.path.join(os.path.expanduser('~'), '.pivtool')
_settings = QtCore.QSettings(os.path.join(CONFIG_HOME, 'settings.ini'),
                             QtCore.QSettings.IniFormat)
_mutex = QtCore.QMutex(QtCore.QMutex.Recursive)


Setting = namedtuple('Setting', 'key default type')


class SETTINGS:
    ALGORITHM = Setting('algorithm', 'RSA2048', str)
    CARD_READER = Setting('card_reader', None, str)
    CERTREQ_TEMPLATE = Setting('certreq_template', None, str)
    COMPLEX_PINS = Setting('complex_pins', False, bool)
    ENABLE_IMPORT = Setting('enable_import', True, bool)
    ENABLE_OUT_CA = Setting('enable_out_ca', platform == 'win32', bool)
    ENABLE_OUT_CSR = Setting('enable_out_csr', True, bool)
    ENABLE_OUT_PK = Setting('enable_out_pk', False, bool)
    ENABLE_OUT_SSC = Setting('enable_out_ssc', True, bool)
    PIN_AS_KEY = Setting('pin_as_key', True, bool)
    PIN_EXPIRATION = Setting('pin_expiration', 0, int)
    SHOWN_SLOTS = Setting('shown_slots', sorted(CERT_SLOTS.keys()), list)
    SUBJECT = Setting('subject', '/CN=%s' % getuser(), str)


def get_store(group):
    return PySettings(SettingsGroup(_settings, _mutex, group))


def convert_to(value, target_type):
    if target_type is list:
        return [] if value is None else [value]
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    if target_type is bool:
        return value not in ['', 'false', 'False']
    return value


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

    def value(self, setting, default=None):
        """Give preference to master."""
        key, default, d_type = setting
        val = self._master.value(key, self._overlay.value(key, default))
        if not isinstance(val, d_type):
            val = convert_to(val, d_type)
        return val

    def setValue(self, setting, value):
        self._overlay.setValue(setting.key, value)

    def remove(self, setting):
        self._overlay.remove(setting.key)

    def childKeys(self):
        """Combine keys of master and overlay."""
        return list(set(self._master.childKeys() + self._overlay.childKeys()))

    def is_locked(self, setting):
        return self._master.contains(setting.key)

    def __repr__(self):
        return 'Overlay(%s, %s)' % (self._master, self._overlay)


class PySettings(MutableMapping):

    def __init__(self, settings):
        self._settings = settings

    def __getattr__(self, method_name):
        return getattr(self._settings, method_name)

    def get(self, key, default=None):
        val = self._settings.value(key, default)
        if not isinstance(val, type(default)):
            val = convert_to(val, type(default))
        return val

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
        return 'PySettings(%s)' % self._settings


settings = PySettings(SettingsOverlay(
    QtCore.QSettings(m.organization, m.app_name),
    get_store('settings')
))
