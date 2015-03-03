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

from pivtool.utils import complexity_check, test, der_read
from pivtool.piv import PivError
from pivtool.storage import settings
from pivtool import messages as m
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from getpass import getuser
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from datetime import datetime, timedelta
import os
import tempfile
import time
import struct
import subprocess


YKPIV_OBJ_PIVTOOL_DATA = 0x5fff00

TAG_PIVTOOL_DATA = 0x80  # Wrapper for PIV tool data
TAG_FLAGS_1 = 0x81  # Flags 1
TAG_SALT = 0x82  # Salt used for management key derivation
TAG_PIN_TIMESTAMP = 0x83  # When the PIN was last changed

FLAG1_PIN_AS_KEY = 0x01  # Derive management key from PIN


def parse_pivtool_data(raw_data):
    rest, _ = der_read(raw_data, TAG_PIVTOOL_DATA)
    data = {}
    while rest:
        t, v, rest = der_read(rest)
        data[t] = v
    return data


def serialize_pivtool_data(data):  # NOTE: Doesn't support values > 0x80 bytes.
    buf = ''.join([chr(k) + chr(len(v)) + v for k, v in sorted(data.items())])
    return chr(TAG_PIVTOOL_DATA) + chr(len(buf)) + buf


def flag_set(data, flagkey, flagmask):
    flags = ord(data.get(flagkey, chr(0)))
    return bool(flags & flagmask)


def set_flag(data, flagkey, flagmask, value=True):
    flags = ord(data.get(flagkey, chr(0)))
    if value:
        flags |= flagmask
    else:
        flags &= ~flagmask
    data[flagkey] = chr(flags)


def derive_key(password, salt):
    if isinstance(password, unicode):
        password = password.encode('utf8')
    return PBKDF2(password, salt, 24, 10000)


def request_cert_from_ca(csr, cert_tmpl):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(csr)
            csr_fn = f.name

        with tempfile.NamedTemporaryFile() as f:
            cert_fn = f.name

        p = subprocess.Popen(['certreq', '-submit', '-attrib',
                              'CertificateTemplate:%s' % cert_tmpl, csr_fn,
                              cert_fn], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise ValueError(m.certreq_error_1 % out)

        with open(cert_fn, 'r') as cert:
            return cert.read()
    except OSError as e:
        raise ValueError(m.certreq_error_1 % e)
    finally:
        os.remove(csr_fn)
        if os.path.isfile(cert_fn):
            os.remove(cert_fn)


def rename_group(old_name, new_name):
    data = {}
    try:
        settings.beginGroup(old_name)
        for key in settings.allKeys():
            data[key] = settings.value(key)
    finally:
        settings.endGroup()
    settings.remove(old_name)

    try:
        settings.beginGroup(new_name)
        for key in data:
            settings.setValue(key, data[key])
    finally:
        settings.endGroup()


class Controller(object):

    def __init__(self, key, window=None):
        self._key = key
        self._window = window
        try:
            self._raw_data = self._key.fetch_object(YKPIV_OBJ_PIVTOOL_DATA)
            self._data = parse_pivtool_data(self._raw_data)
        except PivError:
            self._raw_data = ''
            self._data = {}

    def get(self, key, default=None):
        return settings.value('%s/%s' % (self._key.chuid, key), default)

    def __setitem__(self, key, value):
        settings.setValue('%s/%s' % (self._key.chuid, key), value)

    def __delitem__(self, key):
        settings.remove('%s/%s' % (self._key.chuid, key))

    def __getitem__(self, key):
        return self.get(key)

    def __nonzero__(self):
        return True

    def __len__(self):
        try:
            settings.beginGroup('%s' % self._key.chuid)
            return len(settings.childKeys())
        finally:
            settings.endGroup()

    def _save_data(self):
        raw_data = serialize_pivtool_data(self._data)
        if raw_data != self._raw_data:
            self._key.save_object(YKPIV_OBJ_PIVTOOL_DATA, raw_data)
            self._raw_data = raw_data

    def _authenticate(self, pin=None):
        if TAG_SALT in self._data:
            if flag_set(self._data, TAG_FLAGS_1, FLAG1_PIN_AS_KEY):
                password = pin
            else:
                password, status = QtGui.QInputDialog.getText(
                    self._window, m.enter_key, m.key_label,
                    QtGui.QLineEdit.Password)
                if not status:
                    raise ValueError('No password given!')
            self._key.authenticate(derive_key(password, self._data[TAG_SALT]))
        elif test(self._key.authenticate, catches=PivError):  # Try default key
            pass
        else:  # Ask user
            hex_key, status = QtGui.QInputDialog.getText(
                self._window, m.enter_key, m.key_label)
            if not status:
                raise ValueError('No key given!')

            self._key.authenticate(key_hex.decode('hex'))

    def is_uninitialized(self):
        return not self._data and test(self._key.authenticate)

    def initialize(self, pin, puk=None, hex_key=None, old_pin='123456',
                   old_puk='12345678'):
        if hex_key is None:
            set_flag(self._data, TAG_FLAGS_1, FLAG1_PIN_AS_KEY)
            puk = None  # PUK is worthless if key is derived from PIN
        else:
            set_flag(self._data, TAG_FLAGS_1, FLAG1_PIN_AS_KEY, False)
            self._key.set_authentication(hex_key.decode('hex'))

        if puk is not None:
            self._key.set_puk(old_puk, puk)
        else:
            for i in range(3):  # Invalidate the PUK
                test(self._key.set_puk, '', '', catches=ValueError)

        self.change_pin(old_pin, pin)

    def change_pin(self, old_pin, new_pin):
        if not complexity_check(new_pin):
            raise ValueError(m.pin_not_complex)
        self._key.verify_pin(old_pin)
        self._authenticate(old_pin)
        self._key.set_pin(new_pin)

        # Update management key if needed:
        if flag_set(self._data, TAG_FLAGS_1, FLAG1_PIN_AS_KEY):
            salt = get_random_bytes(16)
            new_key = derive_key(new_pin, salt)
            self._key.set_authentication(new_key)
            self._data[TAG_SALT] = salt

        self._data[TAG_PIN_TIMESTAMP] = struct.pack('i', int(time.time()))
        self._save_data()

    def request_certificate(self, pin, cert_tmpl='User'):
        self._key.verify_pin(pin)
        self._authenticate(pin)
        pubkey = self._key.generate()
        subject = '/CN=%s/' % getuser()
        csr = self._key.create_csr(subject, pubkey)
        cert = request_cert_from_ca(csr, cert_tmpl)
        self._key.import_cert(cert)
        old_chuid = self._key.chuid
        self._key.set_chuid()
        rename_group(old_chuid, self._key.chuid)

    def get_pin_last_changed(self):
        data = self._data.get(TAG_PIN_TIMESTAMP)
        if data is not None:
            data = struct.unpack('i', data)[0]
        return data

    def is_pin_expired(self):
        last_changed = self.get_pin_last_changed()
        if last_changed is None:
            return True
        delta = timedelta(seconds=time.time() - last_changed)
        return delta.days > 30

    def get_certificate_expiration(self, slot='9a'):
        cert = self._key.read_cert(slot)
        if cert is None:
            return None
        cert = decoder.decode(cert, asn1Spec=rfc2459.Certificate())[0]
        expiration = cert['tbsCertificate']['validity']['notAfter']
        value = expiration.getComponentByName(expiration.getName()).asOctets()
        if expiration.getName() == 'utcTime':
            if int(value[0:2]) < 50:
                value = '20' + value
            else:
                value = '19' + value
        if value.endswith('Z'):
            value = value[:-1]
        else:
            # TODO: +/-hhmm
            pass
        dt = datetime.strptime(value + 'GMT', '%Y%m%d%H%M%S%Z')
        return int((dt - datetime.fromtimestamp(0)).total_seconds())

    def is_cert_expired(self, slot='9a'):
        expiry = self.get_certificate_expiration(slot)
        if expiry is None:
            return True
        else:
            return time.time() > expiry
