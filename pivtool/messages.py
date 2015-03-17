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
about_1 = "About: %s"
copyright = "Copyright &copy; Yubico"
libraries = "Library versions"
version_1 = "Version: %s"
menu_file = "&File"
menu_help = "&Help"
action_about = "&About"
action_settings = "&Settings"
settings = "Settings"
general = "General"
certificates = "Certificates"
active_directory = "Active Directory"
active_directory_desc = "The following options are used when requesting a " \
    "certificate from the Windows CA"
reader_name = "Card reader name (default: Yubikey)"
no = "no"
ok = "OK"
cancel = "Cancel"
error = "Error"
refresh = "Refresh"
no_key = "No YubiKey found. Please insert a PIV enabled YubiKey..."
key_with_applet_1 = "YubiKey present with applet version: %s"
name = "Name"
name_1 = "Name: %s"
wait = "Please wait..."
device_unplugged = "Unable to communicate with the device, has it been removed?"
certs_loaded_1 = "You have %s certificate(s) loaded."
change_name = "Change name"
change_name_desc = "Change the name of the device."
current_pin_label = "Current PIN:"
current_puk_label = "Current PUK:"
current_key_label = "Current Management Key:"
new_pin_label = "New PIN (4-8 characters):"
new_complex_pin_label = "New PIN (6-8 characters):"
new_key_label = "New Management Key:"
verify_pin_label = "Repeat new PIN:"
pin = "PIN"
pin_label = "PIN:"
pin_days_left_1 = "PIN expires in %s days."
puk = "PUK"
new_puk_label = "PUK (4-8 characters):"
new_complex_puk_label = "PUK (6-8 characters):"
verify_puk_label = "Repeat PUK:"
puk_confirm_mismatch = "PUKs don't match!"
no_puk = "No PUK set"
no_puk_warning = "If you do not set a PUK you will not be able to reset your " \
    "PIN in case it is ever lost. Continue without setting a PUK?"
puk_not_complex = "PUK doesn't meet complexity rules"
initialize = "Device Initialization"
key_type_pin = "PIN (same as above)"
key_type_key = "Key"
key_invalid = "Invalid management key"
key_invalid_desc = "The key you have provided is invalid. It should contain " \
    "exactly 48 hexadecimal characters."
management_key = "Management key"
key_type_label = "Key type:"
key_label = "Key:"
use_pin_as_key = "Use PIN as key"
use_separate_key = "Use a separate key"
randomize = "Randomize"
copy_clipboard = "Copy to clipboard"
change_pin = "Change PIN"
change_puk = "Change PUK"
change_key = "Change Management Key"
change_pin_desc = "Change your PIN"
change_pin_forced_desc = "Your PIN has expired and must now be changed."
changing_pin = "Setting PIN..."
changing_puk = "Setting PUK..."
changing_key = "Setting Management Key..."
initializing = "Initializing..."
pin_changed = "PIN changed"
pin_changed_desc = "Your PIN has been successfully changed."
puk_changed = "PUK changed"
puk_changed_desc = "Your PUK has been successfully changed."
key_changed = "Management key changed"
key_changed_desc = "Your management key has been successfully changed."
pin_not_changed = "PIN not changed"
pin_not_changed_desc = "New PIN must be different from old PIN"
puk_not_changed = "PUK not changed"
puk_not_changed_desc = "New PUK must be different from old PUK"
pin_confirm_mismatch = "PINs don't match!"
pin_empty = "PIN is empty"
pin_not_complex = "PIN doesn't meet complexity rules"
pin_complexity_desc = """Your PIN/Password must:

* Not contain all or part of the user's account name
* Be at least six characters in length
* Contain characters from three of the following four categories:
   * English uppercase characters (A through Z)
   * English lowercase characters (a through z)
   * Base 10 digits (0 through 9)
   * Nonalphanumeric characters (e.g., !, $, #, %)
"""
enter_pin = "Enter PIN"
enter_key = "Enter management key"
manage_pin = "Manage device PINs"
pin_is_key = "PIN is management key."
enter_file_password = "Enter password to unlock file."
password_label = "Password:"
unknown = "Unknown"
change_cert = "Request certificate"
change_cert_warning_1 = "This will generate a new private key and request a " \
    "certificate from the Windows CA, overwriting any previously stored " \
    "credential in slot '%s' of your YubiKey's PIV applet. This action cannot " \
    "be undone."
changing_cert = "Requesting certificate..."
export_to_file = "Export to file"
export_cert = "Export certificate"
import_from_file = "Import from file"
importing_file = "Importing from file..."
unsupported_file = "Unsupported file type"
delete_cert = "Delete certificate"
delete_cert_warning_1 = "This will delete the certificate stored in slot " \
    "'%s' of your YubiKey, and cannot be undone."
deleting_cert = "Deleting certificate..."
cert_exported = "Certificate exported"
cert_exported_desc_1 = "Certificate exported to file: %s"
cert_deleted = "Certificate deleted"
cert_deleted_desc = "Certificate deleted successfully"
cert_not_loaded = "No certificate loaded"
cert_expires_1 = "Certificate expires: %s"
cert_installed = "Certificate installed"
cert_installed_desc = "A new certificate has been installed. You will need " \
    "to unplug, and re-insert your NEO before it can be used."
cert_tmpl = "Certificate Template"
error = "Error"
wrong_key = "Incorrect management key"
communication_error = "Communication error with the device"
ykpiv_error_2 = "YkPiv error %d: %s"
wrong_pin_tries_1 = "PIN verification failed. %d tries remaining"
pin_blocked = "Your PIN has been blocked due to too many incorrect attempts."
pin_too_long = "PIN must be no more than 8 characters long.\n" \
    "NOTE: Special characters may be counted more than once."
puk_too_long = "PUK must be no more than 8 characters long.\n" \
    "NOTE: Special characters may be counted more than once."
certreq_error = "There was an error requesting a certificate."
certreq_error_1 = "Error running certreq: %s"
authentication_error = "Unable to authenticate to device"
use_complex_pins = "Enforce complex PIN/PUKs"
pin_expires = "Force periodic PIN change"
pin_expires_days = "How often (days)?"
issued_to_label = "Issued to:"
issued_by_label = "Issued by:"
valid_from_label = "Valid from:"
valid_to_label = "Valid to:"


def _translate(qt):
    values = globals()
    for key, value in values.items():
        if isinstance(value, basestring) and not key.startswith('_'):
            values[key] = qt.tr(value)
