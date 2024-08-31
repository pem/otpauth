Time-based One-time Password (TOTP) is a common second factor authentication
method, supported by many sites. The user installs a "token" (shared secret
with some other data) in an App, usually by scanning a QR code. (It's
often also possible to enter the code manually.)
See RFC 6238 for technical details.

Hash-based One-time Password (HOTP) is not commonly used, but it's the basis
for the TOTP mathod. The "hash" is a Hash-based Message Authenticaion Code
(HMAC), used to hash a counter.
See RFC 4226 for technical details.

This modul implements TOTP, HOTP, as well as methods for generating a secret
and URI that can be turned into a QR code for scanning.

Example TOTP usage with default values:

- Generate an 160 bit secret (to be stored at the server end for future
  verifications):
    s = OTPAuth.generate_secret(20)

- Generate an URI for QR-coding (to be presented to the user for scanning):
    u = OTPAuth.totp_uri(s, "My Issuer Name", "Some Label")

- Verify a TOTP code "c" from the user:
    if c == OTPAuth.totp(s)
       puts "Ok"
    else
      puts "Not ok"
    end
