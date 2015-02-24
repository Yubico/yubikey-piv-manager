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

"""
Strings for Yubico pivtool GUI.

Note: String names must not start with underscore (_).

"""

organization = "Yubico"
domain = "yubico.com"
app_name = "Yubico PIV tool"
win_title_1 = "Yubico PIV tool (%s)"
ok = "OK"
cancel = "Cancel"
error = "Error"
refresh = "Refresh"
no_key = "No YubiKey found. Please insert a PIV enabled YubiKey and try again."
name = "Name"
name_1 = "Name: %s"
wait = "Please wait..."
change_name = "Change name"
change_name_desc = "Change the name of the device."
current_pin_label = "Current PIN:"
new_pin_label = "New PIN (6-8 characters):"
verify_pin_label = "Repeat new PIN:"
pin_label = "PIN:"
pin_last_changed_1 = "PIN last changed: %s"
set_pin = "Please set up your device with a PIN to get started."
change_pin = "Change PIN"
change_pin_desc = "Change your PIN"
change_pin_forced_desc = "Your PIN has expired and must now be changed."
changing_pin = "Setting PIN..."
pin_changed = "PIN changed"
pin_changed_desc = "The PIN has been successfully changed."
pin_not_changed = "PIN not changed"
pin_not_changed_desc = "New PIN must be different from old PIN"
pin_not_complex = "PIN doesn't meet complexity rules"
pin_complexity_desc = """
Your PIN must:
* Not contain all or part of the user's account name
* Be at least six characters in length
* Contain characters from three of the following four categories:
   * English uppercase characters (A through Z)
   * English lowercase characters (a through z)
   * Base 10 digits (0 through 9)
   * Nonalphanumeric characters (e.g., !, $, #, %)
"""
enter_pin = "Enter PIN"
unknown = "Unknown"
change_cert = "Request certificate"
change_cert_warning = "This will generate a new private key and request a " \
    "certificate from the Windows CA, overwriting any previously stored " \
    "credential in slot 9a of your YubiKey's PIV applet. This action cannot " \
    "be undone."
changing_cert = "Requesting certificate..."
cert_expires_1 = "Certificate expires: %s"
cert_installed = "Certificate installed"
cert_installed_desc = "A new certificate has been installed."


def _translate(qt):
    values = globals()
    for key, value in values.items():
        if isinstance(value, basestring) and not key.startswith('_'):
            values[key] = qt.tr(value)
