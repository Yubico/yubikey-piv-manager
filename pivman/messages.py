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
Strings for YubiKey PIV Manager.

Note: String names must not start with underscore (_).

"""

organization = "Yubico"
domain = "yubico.com"
app_name = "YubiKey PIV Manager"
win_title_1 = "YubiKey PIV Manager (%s)"
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
misc = "Miscellaneous"
certificates = "Certificates"
active_directory = "Active Directory"
active_directory_desc = "The following options are used when requesting a " \
    "certificate from the Windows CA"
reader_name = "Card reader name"
no = "no"
ok = "OK"
cancel = "Cancel"
error = "Error"
refresh = "Refresh"
no_key = "No YubiKey found. Please insert a PIV enabled YubiKey..."
key_with_applet_1 = "YubiKey present with applet version: %s."
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
new_pin_label = "New PIN (6-8 characters):"
new_key_label = "New Management Key:"
verify_pin_label = "Repeat new PIN:"
pin = "PIN"
pin_label = "PIN:"
pin_days_left_1 = "PIN expires in %s days."
puk = "PUK"
puk_label = "PUK:"
new_puk_label = "PUK (6-8 characters):"
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
key_label = "Management Key:"
use_pin_as_key = "Use PIN as key"
use_separate_key = "Use a separate key"
randomize = "Randomize"
copy_clipboard = "Copy to clipboard"
change_pin = "Change PIN"
reset_pin = "Reset PIN"
reset_device = "Reset device"
reset_device_warning = "This will erase all data including keys and " \
    "certificates from the device. Your PIN, PUK and Management Key will be " \
    "reset to the factory defaults."
resetting_device = "Resetting device..."
device_resetted = "Device reset complete"
device_resetted_desc = "Your device has now been reset, and will require " \
    "initialization."
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
pin_puk_same = "PIN and PUK the same"
pin_puk_same_desc = "PIN and PUK must be different"
puk_blocked = "PUK is blocked."
block_puk = "PUK will be blocked"
block_puk_desc = "Using your PIN as Management Key will block your PUK. " \
    "You will not be able to recover your PIN if it is lost. A blocked PUK " \
    "cannot be unblocked, even by setting a new Management Key."
pin_confirm_mismatch = "PINs don't match!"
pin_empty = "PIN is empty"
pin_not_complex = "PIN doesn't meet complexity rules"
pin_complexity_desc = """Your PIN/PUK must:

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
    "credential in slot '%s' of your YubiKey's PIV applet. This action " \
    "cannot be undone."
changing_cert = "Requesting certificate..."
export_to_file = "Export certificate..."
export_cert = "Export certificate"
save_pk = "Save Public Key as..."
save_csr = "Save Certificate Signing Request as..."
generate_key = "Generate new key..."
generate_key_warning_1 = "A new private key will be generated and stored in " \
    "slot '%s'. Anything currently in the slot will be deleted. This action " \
    "cannot be undone."
generating_key = "Generating new key..."
generated_key = "New key generated"
generated_key_desc_1 = "A new private key has been generated in slot '%s'."
gen_out_pk_1 = "The corresponding public key has been saved to:\n%s"
gen_out_csr_1 = "A certificate signing request has been saved to:\n%s"
gen_out_ssc = "A self-signed certificate has been loaded."
gen_out_ca = "A certificate from the CA has been loaded."
import_from_file = "Import from file..."
import_from_file_warning_1 = "Anything currently in slot '%s' will be " \
    "overwritten by the imported content. This action cannot be undone."
importing_file = "Importing from file..."
unsupported_file = "Unsupported file type"
delete_cert = "Delete certificate"
delete_cert_warning_1 = "This will delete the certificate  and key stored in " \
    "slot '%s' of your YubiKey, and cannot be undone."
deleting_cert = "Deleting certificate..."
cert_exported = "Certificate exported"
cert_exported_desc_1 = "Certificate exported to file: %s"
cert_deleted = "Certificate deleted"
cert_deleted_desc = "Certificate deleted successfully"
cert_not_loaded = "No certificate loaded."
cert_expires_1 = "Certificate expires: %s"
cert_installed = "Certificate installed"
cert_installed_desc = "A new certificate has been installed. You may need to " \
    "unplug and re-insert your YubiKey before it can be used."
cert_tmpl = "Certificate Template"
subject = "Subject"
error = "Error"
wrong_key = "Incorrect management key"
communication_error = "Communication error with the device"
ykpiv_error_2 = "YkPiv error %d: %s"
wrong_pin_tries_1 = "PIN verification failed. %d tries remaining"
wrong_puk_tries_1 = "PUK verification failed. %d tries remaining"
pin_blocked = "Your PIN has been blocked due to too many incorrect attempts."
pin_too_long = "PIN must be no more than 8 characters long.\n" \
    "NOTE: Special characters may be counted more than once."
puk_too_long = "PUK must be no more than 8 characters long.\n" \
    "NOTE: Special characters may be counted more than once."
certreq_error = "There was an error requesting a certificate."
certreq_error_1 = "Error running certreq: %s"
ca_not_connected = "You currently do not have a connection to a " \
    "Certification Authority."
authentication_error = "Unable to authenticate to device"
use_complex_pins = "Enforce complex PIN/PUKs"
pin_expires = "Force periodic PIN change"
pin_expires_days = "How often (days)?"
issued_to_label = "Issued to:"
issued_by_label = "Issued by:"
valid_from_label = "Valid from:"
valid_to_label = "Valid to:"
usage_9a = "The X.509 Certificate for PIV Authentication and its associated " \
    "private key, as defined in FIPS 201, is used to authenticate the card " \
    "and the cardholder."
usage_9c = "The X.509 Certificate for Digital Signature and its associated " \
    "private key, as defined in FIPS 201, support the use of digital " \
    "signatures for the purpose of document signing. "
usage_9d = "The X.509 Certificate for Key Management and its associated " \
    "private key, as defined in FIPS 201, support the use of encryption for " \
    "the purpose of confidentiality."
usage_9e = "FIPS 201 specifies the optional Card Authentication Key (CAK) as " \
    "an asymmetric or symmetric key that is used to support additional " \
    "physical access applications. "
algorithm = "Algorithm"
alg_rsa_1024 = "RSA (1024 bits)"
alg_rsa_2048 = "RSA (2048 bits)"
alg_ecc_p256 = "ECC (P-256)"
alg_ecc_p384 = "ECC (P-384)"
algorithm_1 = "Algorithm: %s"
output = "Output"
out_pk = "Public key"
out_csr = "Certificate Signing Request (CSR)"
out_ssc = "Create a self-signed certificate"
out_ca = "Request a certificate from a Windows CA"
no_output = "Your configuration does not allow any valid output format."
invalid_subject = "Invalid subject"
invalid_subject_desc = """The subject must be written as:
/CN=host.example.com/OU=test/O=example.com"""
usage_policy = "Usage policy"
pin_policy = "Require PIN"
pin_policy_1 = "Require PIN: %s"
pin_policy_default = "Slot default"
pin_policy_never = "Never"
pin_policy_once = "Once"
pin_policy_always = "Always"
touch_policy = "Require button touch"
touch_needed = "User action needed"
touch_needed_desc = "You have chosen to require user interaction to use this " \
    "certificate. Once you close this dialog, the light on your YubiKey " \
    "will start slowly blinking. At that point please touch the button on " \
    "your YubiKey."
touch_prompt = "Touch the button now..."
expiration_date = "Expiration date"
setting_up_macos = "Setting up for macOS..."
macos_pairing_title = "Generate certificates for macOS"
macos_pairing_desc = "Your version of macOS allows you to pair your YubiKey " \
        "with your user account. " \
        "This allows you to use your YubiKey for operating system tasks such "\
        "as login. " \
        "To enable this the YubiKey requires certificates in the slots for " \
        "authentication and key management.\n\n" \
        "Do you wish to generate self-signed certificates "\
        "for these slots (recommended)?"
setup_for_macos = "Setup for macOS"
setup_macos_compl = "Setup for macOS completed"
setup_macos_compl_desc = "Your YubiKey is now setup for pairing with macOS. " \
        "To start the pairing process, please remove and re-insert " \
        "your YubiKey."
