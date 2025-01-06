import etokenng
import pyotp, base64

param = {'debug': 'debug', 'userpin': b'12345ABCabc'}
enroller = etokenng.etng(param)

enroller.initpkcs11()
enroller.logintoken(1) ### Must be 0...

enroller.deleteOTP()
key = enroller.createKey()
enroller.createOTP(key = key, initial_count = 0)
enroller.logouttoken()

# Verify
hotp = pyotp.HOTP(base64.b32encode(key), initial_count = 0, digits = 6)
print(hotp.at(0)) ### Skipped? Why?
print(hotp.at(1))
print(hotp.at(2))
print(hotp.at(3))
print(hotp.at(4))

