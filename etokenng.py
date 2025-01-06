#    
#    eToken NG-OTP password generator initializer module
#    https://github.com/kaseiiro/et_otp_demo
#    Based on privacyIDEA and LinOTP code snippets.
#    License:  AGPLv3
#    
#    privacyIDEA is a fork of LinOTP
#    Dec 01, 2014 Cornelius Kölbel
#    License:  AGPLv3
#    contact:  http://www.privacyidea.org
#
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
Aladdin eToken NG OTP setup
"""
from ctypes import *
import platform
import gettext

CKF_RW_SESSION                          = 0x00000002
CKF_SERIAL_SESSION                      = 0x00000004
CK_SAPI_OTP_HMAC_SHA1_DEC6              = 0x00000001
CKA_SAPI_OTP_MECHANISM                  = int(0x80001301)
CKA_SAPI_OTP_COUNTER                    = int(0x80001302)
CKA_SAPI_OTP_DURATION                   = int(0x80001303)
CKA_SAPI_OTP_VALUE                      = int(0x80001304)
CKA_SAPI_OTP_CURRENT_ALLOWED            = int(0x80001305)
CKA_SAPI_OTP_NEXT_ALLOWED               = int(0x80001306)
CKA_SAPI_OTP_ZERO_ALLOWED               = int(0x80001307)
CKA_SAPI_OTP_CUSTOM_DURATION_ALLOWED    = int(0x80001308)

CKR_MECHANISM_INVALID                   = int(0x00000070)

CKU_USER		 = 1
CKU_SO			 = 0

NULL = None

_ = gettext.gettext


#typedef CK_ULONG          CK_FLAGS;



class CK_ATTRIBUTE(Structure):
    _pack_ = 1
    _fields_ = [("type", c_ulong),
                ("pValue", c_void_p),
                ("ulValueLen", c_ulong),
                ]
                


class etngError(Exception):

    def __init__(self, id=10, description="etngError"):
        self.id = id
        self.description = description

    def __str__(self):
        ## here we lookup the error id - to translate
        return repr("ERR" + str(self.id) + ": " + self.description)


class etng(object):
  errormap = { 182:_('Session exists'),
                7:_('Bad argument'),
                19: _('Attribute value invalid'),
                162: _('invalid PIN length'),
                112: _('Mechanism invalid'),
                224: _('Token not present'),
                209: _('Template inconsistent'),
                208: _('Template incomplete'),
                163: _('PIN expired'),
                160: _('Unknown initializazion key')
                }

  def __init__(self, param):
    self.debug = False
    self.password = ""
    self.connectedTokens = []

    # check params
    if 'debug' in param:
        self.debug = param['debug']
    if 'userpin' in param:
        self.password = param['userpin']

    self.tdata = { 'hmac':'', 'password':'', 'serial':'', 'error':'', 'sopassword':''}

    system = platform.system()
    if system == "Windows":
        #self.etpkcs11 = CDLL("eTPkcs11")
        self.etoken = CDLL("etoken")
        #self.etsapi = CDLL("eTSapi")
    else:
        raise etngError(2020, _("etng::__init__ - Unknown system platform (%s)") % system)
    self.hSession = c_ulong()

  def pkcs11error(self, rv):
    if rv in self.errormap:
        return self.errormap[rv]
    else:
        return rv

  def initpkcs11(self):
    self.etoken.C_Initialize(0)
    self.connectedTokens = []
    # Get the number of connected Tokens
    prototype = CFUNCTYPE (c_int, c_int, POINTER(c_ulong), POINTER(c_ulong))
    paramflags = (1, "tokenPresent", 1), (2, "SlotID"), (2, "nSlots")
    getslotlist = prototype(("C_GetSlotList", self.etoken) , paramflags)

    (SlotID, nSlots) = getslotlist()
    if self.debug: print("Number of connected tokens: " , nSlots)
    if self.debug: print("SlotID: " , SlotID)

    if nSlots > 1:
        raise etngError(2020, _("etng::initpkcs11 - There are more than one tokens connected (%s)") % nSlots)

    if nSlots == 0:
        self.tdata['error'] = "No token connected"


  def logintoken(self, SlotID = 0):
    # Open a session on fist token
    prototype = CFUNCTYPE (c_int, c_int, c_int, POINTER(c_ulong), POINTER(c_ulong), POINTER(c_ulong))
    paramflags = (1, "SlotID", 0), (1, "Flags", CKF_RW_SESSION | CKF_SERIAL_SESSION), (1, "App", NULL), (1, "Notify", NULL), (2, "SessionHandle")
    opensession = prototype(("C_OpenSession", self.etoken), paramflags)
    self.hSession = opensession(SlotID)

    #print(self.password)
    #print(len(self.password))

    rv = self.etoken.C_Login(self.hSession, CKU_USER, self.password, len(self.password))
    if rv:
        if self.debug: print("Failed to login to token: " , rv)
        raise etngError(2004, _("etng::logintoken - Failed to C_Login (%s)") % rv)
    else:
        if self.debug:
            print("Login succesful")
            
  def logouttoken(self):
    rv = self.etoken.C_Logout(self.hSession)
    if rv:
        if self.debug: print("Failed to logout from token: " , rv)
        raise etngError(2004, _("etng::logouttoken - Failed to C_Logout (%s)") % rv)
    else:
        if self.debug:
            print("Logout succesful")

  def deleteOTP(self):
    # Deleting existing OTP appliacion
    if self.debug: print("Deleting possible existing OTP application on the token")
    self.etoken.SAPI_OTP_Destroy(self.hSession)

  def createKey(self):
  
    if self.debug: print("Creating a random key")
    
    #Java Card OTP  20..24
    #CardOS OTP     20..32

    key_size = 24 ## TODO
    key = b'\x00' * key_size

    if self.debug: print(f"Sizeof key: {len(key)}.")

    rv = self.etoken.C_GenerateRandom(self.hSession, key, c_ulong(len(key)))

    if rv:
        if self.debug: print("C_GenerateRandom failed:", rv)
        raise etngError(2005, _("etng::deleteOTP - Failed to C_GenerateRandom (%s)") % rv)
    else:
        if self.debug: print(f"Created random {len(key)} bytes HMAC key: {key.hex()}.")
        
    return key


  def createOTP(self, key = b'\x00' * 24, initial_count = 0, show_duration = 5):

    if self.debug: print("Creating new OTP object")

    p_c_key = c_char_p(key)
    
    ck_mech = c_ulong(CK_SAPI_OTP_HMAC_SHA1_DEC6)
    ck_current_allowed = c_ubyte(True)
    ck_next_allowed = c_ubyte(False)
    ck_zero_allowed = c_ubyte(True)
    print(len(key))
    ck_duration = c_ulong(int(show_duration))
    ck_counter = c_ulong(int(initial_count))
    tCreate = [
        CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_MECHANISM),       cast(byref(ck_mech), c_void_p),             c_ulong(sizeof(ck_mech))),
        CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_VALUE),           cast(p_c_key, c_void_p),                    c_ulong(len(key))),
        #CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_CURRENT_ALLOWED), cast(byref(ck_current_allowed), c_void_p),  c_ulong(sizeof(ck_current_allowed))),
        #CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_NEXT_ALLOWED),    cast(byref(ck_next_allowed), c_void_p),     c_ulong(sizeof(ck_next_allowed))),
        #CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_ZERO_ALLOWED),    cast(byref(ck_zero_allowed), c_void_p),     c_ulong(sizeof(ck_zero_allowed))),
        CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_DURATION),        cast(byref(ck_duration), c_void_p),         c_ulong(sizeof(ck_duration))),
        CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_COUNTER),         cast(byref(ck_counter), c_void_p),          c_ulong(sizeof(ck_counter))),
    ]
    arrayCK_ATTRIBUTES = CK_ATTRIBUTE * len(tCreate)
    tCreate = arrayCK_ATTRIBUTES(*tCreate)

    #print(c_ulong(len(tCreate)))
    #print(bytearray(tCreate).hex())

    rv = self.etoken.SAPI_OTP_Create(self.hSession, tCreate, c_ulong(len(tCreate)))

    if rv:
        rv = self.pkcs11error(rv)
        if self.debug: print("Error creating OTP object: ", rv)
        raise etngError(2006, _("etng::createOTP - Failed to etoken.SAPI_OTP_Create (%s). Maybe the token was initialized previously without HMAC support?") % rv)
    else:
        if self.debug: print("OTP object created successfully")


