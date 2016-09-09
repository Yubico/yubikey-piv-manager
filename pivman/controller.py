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

from pivman.utils import test, der_read, is_macos_sierra_or_later
from pivman.piv import PivError, WrongPinError
from pivman.storage import settings, SETTINGS
from pivman.view.utils import get_active_window, get_text
from pivman import messages as m
from pivman.yubicommon.compat import text_type, byte2int, int2byte
from PySide import QtGui, QtNetwork
from datetime import timedelta
from hashlib import pbkdf2_hmac
from binascii import a2b_hex
import os
import re
import time
import struct

YKPIV_OBJ_PIVMAN_DATA = 0x5fff00

TAG_PIVMAN_DATA = 0x80  # Wrapper for pivman data
TAG_FLAGS_1 = 0x81  # Flags 1
TAG_SALT = 0x82  # Salt used for management key derivation
TAG_PIN_TIMESTAMP = 0x83  # When the PIN was last changed

FLAG1_PUK_BLOCKED = 0x01  # PUK is blocked

AUTH_SLOT = '9a'
ENCRYPTION_SLOT = '9d'
DEFAULT_AUTH_SUBJECT = "/CN=Yubico PIV Authentication"
DEFAULT_ENCRYPTION_SUBJECT = "/CN=Yubico PIV Encryption"
DEFAULT_VALID_DAYS = 10950  # 30 years


def parse_pivtool_data(raw_data):
    rest, _ = der_read(raw_data, TAG_PIVMAN_DATA)
    data = {}
    while rest:
        t, v, rest = der_read(rest)
        data[t] = v
    return data


def serialize_pivtool_data(data):  # NOTE: Doesn't support values > 0x80 bytes.
    buf = b''
    for k, v in sorted(data.items()):
        buf += int2byte(k) + int2byte(len(v)) + v
    return int2byte(TAG_PIVMAN_DATA) + int2byte(len(buf)) + buf


def has_flag(data, flagkey, flagmask):
    flags = byte2int(data.get(flagkey, b'\0')[0])
    return bool(flags & flagmask)


def set_flag(data, flagkey, flagmask, value=True):
    flags = byte2int(data.get(flagkey, b'\0')[0])
    if value:
        flags |= flagmask
    else:
        flags &= ~flagmask
    data[flagkey] = int2byte(flags)


def derive_key(pin, salt):
    if pin is None:
        raise ValueError('PIN must not be None!')
    if isinstance(pin, text_type):
        pin = pin.encode('utf8')
    return pbkdf2_hmac('sha1', pin, salt, 10000, dklen=24)


def is_hex_key(string):
    try:
        return bool(re.compile(r'^[a-fA-F0-9]{48}$').match(string))
    except:
        return False


class Controller(object):

    def __init__(self, key):
        self._key = key
        self._authenticated = False
        try:
            self._raw_data = self._key.fetch_object(YKPIV_OBJ_PIVMAN_DATA)
            # TODO: Remove in a few versions...
            if byte2int(self._raw_data[0]) != TAG_PIVMAN_DATA:
                self._data = {}
                self._data[TAG_PIN_TIMESTAMP] = self._raw_data
                self._data[TAG_SALT] = self._key.fetch_object(
                    YKPIV_OBJ_PIVMAN_DATA + 1)
            else:
                # END legacy stuff
                self._data = parse_pivtool_data(self._raw_data)
        except PivError:
            self._raw_data = serialize_pivtool_data({})
            self._data = {}

    def poll(self):
        return test(self._key._read_version)

    def reconnect(self):
        self._key.reconnect()

    def _save_data(self):
        raw_data = serialize_pivtool_data(self._data)
        if raw_data != self._raw_data:
            self.ensure_authenticated()
            self._key.save_object(YKPIV_OBJ_PIVMAN_DATA, raw_data)
            self._raw_data = raw_data

    @property
    def version(self):
        return self._key.version

    @property
    def version_tuple(self):
        return tuple(map(int, self.version.split(b'.')))

    @property
    def authenticated(self):
        return self._authenticated

    @property
    def pin_is_key(self):
        return TAG_SALT in self._data

    @property
    def pin_blocked(self):
        return self._key.pin_blocked

    @property
    def puk_blocked(self):
        return has_flag(self._data, TAG_FLAGS_1, FLAG1_PUK_BLOCKED)

    def verify_pin(self, pin):
        if len(pin) > 8:
            raise ValueError('PIN must be no longer than 8 bytes!')
        self._key.verify_pin(pin)

    def ensure_pin(self, pin=None, window=None):
        if window is None:
            window = get_active_window()

        if pin is not None:
            try:
                self.verify_pin(pin)
                return pin
            except WrongPinError as e:
                if e.blocked:
                    raise
                QtGui.QMessageBox.warning(window, m.error, str(e))
            except ValueError as e:
                QtGui.QMessageBox.warning(window, m.error, str(e))

        pin, status = get_text(
            window, m.enter_pin, m.pin_label, QtGui.QLineEdit.Password)
        if not status:
            raise ValueError('PIN entry aborted!')
        return self.ensure_pin(pin, window)

    def ensure_authenticated(self, key=None, window=None):
        if self.authenticated or test(self.authenticate, catches=ValueError):
            return

        if window is None:
            window = get_active_window()

        if self.pin_is_key:
            key = self.ensure_pin(key, window)
            self.authenticate(key)
            return
        elif key is not None:
            try:
                self.authenticate(key)
                return
            except ValueError:
                pass

        self._do_ensure_auth(None, window)

    def _do_ensure_auth(self, key, window):
        if key is not None:
            try:
                self.authenticate(key)
                return
            except ValueError as e:
                QtGui.QMessageBox.warning(window, m.error, str(e))

        key, status = get_text(window, m.enter_key, m.key_label)
        if not status:
            raise ValueError('Key entry aborted!')
        self._do_ensure_auth(key, window)

    def reset_device(self):
        self._key.reset_device()

    def authenticate(self, key=None):
        salt = self._data.get(TAG_SALT)

        if key is not None and salt is not None:
            key = derive_key(key, salt)
        elif is_hex_key(key):
            key = a2b_hex(key)

        self._authenticated = False
        if test(self._key.authenticate, key, catches=PivError):
            self._authenticated = True
        else:
            raise ValueError(m.wrong_key)

    def is_uninitialized(self):
        return not self._data and test(self._key.authenticate)

    def _invalidate_puk(self):
        set_flag(self._data, TAG_FLAGS_1, FLAG1_PUK_BLOCKED)
        for i in range(8):  # Invalidate the PUK
            test(self._key.set_puk, '', '000000', catches=ValueError)

    def initialize(self, pin, puk=None, key=None, old_pin='123456',
                   old_puk='12345678'):

        if not self.authenticated:
            self.authenticate()

        if key is None:  # Derive key from PIN
            self._data[TAG_SALT] = b''  # Used as a marker for change_pin
        else:
            self.set_authentication(key)
            if puk is None:
                self._invalidate_puk()
            else:
                self._key.set_puk(old_puk, puk)

        self.change_pin(old_pin, pin)

    def setup_for_macos(self, pin):

        """Generate self-signed certificates in slot 9a and 9d
        to allow pairing a YubiKey with a user account on macOS"""

        auth_key = self.generate_key(AUTH_SLOT)
        auth_cert = self.selfsign_certificate(
            AUTH_SLOT, pin, auth_key,
            DEFAULT_AUTH_SUBJECT, DEFAULT_VALID_DAYS)
        self.import_certificate(auth_cert, AUTH_SLOT)

        encryption_key = self.generate_key(ENCRYPTION_SLOT)
        encryption_cert = self.selfsign_certificate(
            ENCRYPTION_SLOT, pin, encryption_key,
            DEFAULT_ENCRYPTION_SUBJECT, DEFAULT_VALID_DAYS)
        self.import_certificate(encryption_cert, ENCRYPTION_SLOT)

    def set_authentication(self, new_key, is_pin=False):
        if not self.authenticated:
            raise ValueError('Not authenticated')

        if is_pin:
            self.verify_pin(new_key)
            salt = os.urandom(16)
            key = derive_key(new_key, salt)
            self._data[TAG_SALT] = salt
            self._key.set_authentication(key)

            # Make sure PUK is invalidated:
            if not has_flag(self._data, TAG_FLAGS_1, FLAG1_PUK_BLOCKED):
                self._invalidate_puk()
        else:
            if is_hex_key(new_key):
                new_key = a2b_hex(new_key)

            self._key.set_authentication(new_key)
            if self.pin_is_key:
                del self._data[TAG_SALT]

        self._save_data()

    def change_pin(self, old_pin, new_pin):
        if len(new_pin) < 6:
            raise ValueError('PIN must be at least 6 characters')
        self.verify_pin(old_pin)
        if self.pin_is_key or self.does_pin_expire():
            self.ensure_authenticated(old_pin)
        self._key.set_pin(new_pin)
        # Update management key if needed:
        if self.pin_is_key:
            self.set_authentication(new_pin, True)

        if self.does_pin_expire():
            self._data[TAG_PIN_TIMESTAMP] = struct.pack('i', int(time.time()))
        self._save_data()

    def reset_pin(self, puk, new_pin):
        if len(new_pin) < 6:
            raise ValueError('PIN must be at least 6 characters')
        try:
            self._key.reset_pin(puk, new_pin)
        except WrongPinError as e:
            if e.blocked:
                set_flag(self._data, TAG_FLAGS_1, FLAG1_PUK_BLOCKED)
            raise

    def change_puk(self, old_puk, new_puk):
        if self.puk_blocked:
            raise ValueError('PUK is disabled and cannot be changed')
        if len(new_puk) < 6:
            raise ValueError('PUK must be at least 6 characters')
        try:
            self._key.set_puk(old_puk, new_puk)
        except WrongPinError as e:
            if e.blocked:
                set_flag(self._data, TAG_FLAGS_1, FLAG1_PUK_BLOCKED)
            raise

    def update_chuid(self):
        if not self.authenticated:
            raise ValueError('Not authenticated')
        self._key.set_chuid()

    def generate_key(self, slot, algorithm='RSA2048', pin_policy=None,
                     touch_policy=False):
        if not self.authenticated:
            raise ValueError('Not authenticated')

        if pin_policy == 'default':
            pin_policy = None

        if slot in self.certs:
            self.delete_certificate(slot)
        return self._key.generate(slot, algorithm, pin_policy, touch_policy)

    def create_csr(self, slot, pin, pubkey, subject):
        self.verify_pin(pin)
        if not self.authenticated:
            raise ValueError('Not authenticated')
        return self._key.create_csr(subject, pubkey, slot)

    def selfsign_certificate(self, slot, pin, pubkey, subject, valid_days=365):
        self.verify_pin(pin)
        if not self.authenticated:
            raise ValueError('Not authenticated')
        return self._key.create_selfsigned_cert(
            subject, pubkey, slot, valid_days)

    def does_pin_expire(self):
        return bool(settings[SETTINGS.PIN_EXPIRATION])

    def get_pin_last_changed(self):
        data = self._data.get(TAG_PIN_TIMESTAMP)
        if data is not None:
            data = struct.unpack('i', data)[0]
        return data

    def get_pin_days_left(self):
        validity = settings[SETTINGS.PIN_EXPIRATION]
        if not validity:
            return -1
        last_changed = self.get_pin_last_changed()
        if last_changed is None:
            return 0
        time_passed = timedelta(seconds=time.time() - last_changed)
        time_left = timedelta(days=validity) - time_passed
        return max(time_left.days, 0)

    def is_pin_expired(self):
        if not self.does_pin_expire():
            return False

        last_changed = self.get_pin_last_changed()
        if last_changed is None:
            return True
        delta = timedelta(seconds=time.time() - last_changed)
        return delta.days > 30

    @property
    def certs(self):
        return self._key.certs

    def get_certificate(self, slot):
        data = self._key.read_cert(slot)
        if data is None:
            return None
        return QtNetwork.QSslCertificate.fromData(data, QtNetwork.QSsl.Der)[0]

    def import_key(self, data, slot, frmt='PEM', password=None, pin_policy=None,
                   touch_policy=False):
        if not self.authenticated:
            raise ValueError('Not authenticated')

        if pin_policy == 'default':
            pin_policy = None

        self._key.import_key(data, slot, frmt, password, pin_policy,
                             touch_policy)

    def import_certificate(self, cert, slot, frmt='PEM', password=None):
        if not self.authenticated:
            raise ValueError('Not authenticated')
        try:
            self._key.import_cert(cert, slot, frmt, password)
        except ValueError:
            if len(cert) > 2048 and self.version_tuple < (4, 2, 7):
                raise ValueError('Certificate is to large to fit in buffer.')
            else:
                raise
        self.update_chuid()

    def delete_certificate(self, slot):
        if not self.authenticated:
            raise ValueError('Not authenticated')
        self._key.delete_cert(slot)

    def should_show_macos_dialog(self):
        return is_macos_sierra_or_later() \
            and AUTH_SLOT not in self.certs \
            and ENCRYPTION_SLOT not in self.certs
