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
from pivman import messages as m
from pivman.piv import CERT_SLOTS
from pivman.yubicommon import qt
from PySide import QtCore
from collections import namedtuple
from getpass import getuser
from sys import platform

__all__ = [
    'CONFIG_HOME',
    'SETTINGS',
    'settings'
]

CONFIG_HOME = os.path.join(os.path.expanduser('~'), '.pivman')


Setting = namedtuple('Setting', 'key default type')

win = platform == 'win32'


def default_outs():
    if win:
        return ['ssc', 'csr', 'ca']
    else:
        return ['ssc', 'csr']


class SETTINGS:
    ALGORITHM = Setting('algorithm', 'RSA2048', str)
    CARD_READER = Setting('card_reader', None, str)
    CERTREQ_TEMPLATE = Setting('certreq_template', None, str)
    COMPLEX_PINS = Setting('complex_pins', False, bool)
    ENABLE_IMPORT = Setting('enable_import', True, bool)
    OUT_TYPE = Setting('out_type', 'ca' if win else 'ssc', str)
    PIN_AS_KEY = Setting('pin_as_key', True, bool)
    PIN_EXPIRATION = Setting('pin_expiration', 0, int)
    PIN_POLICY = Setting('pin_policy', None, str)
    SHOWN_OUT_FORMS = Setting('shown_outs', default_outs(), list)
    SHOWN_SLOTS = Setting('shown_slots', sorted(CERT_SLOTS.keys()), list)
    SUBJECT = Setting('subject', '/CN=%s' % getuser(), str)
    TOUCH_POLICY = Setting('touch_policy', False, bool)


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
            val = qt.convert_to(val, d_type)
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


settings = qt.PySettings(SettingsOverlay(
    QtCore.QSettings(m.organization, m.app_name),
    qt.Settings.wrap(os.path.join(CONFIG_HOME, 'settings.ini'),
                     QtCore.QSettings.IniFormat).get_group('settings')
))
