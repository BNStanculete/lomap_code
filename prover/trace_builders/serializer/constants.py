
# Trace Constants
TRACE_WIDTH         = 475
REGISTER_LIMIT      = pow(2, 64)

# X.509 TAGs
INTEGER             = int('0x02', 16)
NULL                = int('0x05', 16)
OID                 = int('0x06', 16)
UTF8_STRING         = int('0x0C', 16)
PRINTABLE_STRING    = int('0x13', 16)
TELETEX_STRING      = int('0x14', 16)
IA5_STRING          = int('0x16', 16)
UTC_TIME            = int('0x17', 16)
SEQUENCE            = int('0x30', 16)
SET                 = int('0x31', 16)

# X.509 OIDs
OIDs = {
    "SHA256_RSA":   "1.2.840.113549.1.1.11",
    "SHA256_ECDSA": "1.2.840.10045.4.3.2",

    "CN":           "2.5.4.3",
    "C":            "2.5.4.6",
    "ST":           "2.5.4.8",
    "L":            "2.5.4.7",
    "O":            "2.5.4.10",
    "OU":           "2.5.4.11",
    "STREET":       "2.5.4.9",
    "DC":           "0.9.2342.19200300.100.1.25",
    "UID":          "0.9.2342.19200300.100.1.1",
    "SERIALNUMBER": "2.5.4.5",
    "EMAILADDRESS": "1.2.840.113549.1.9.1"
}