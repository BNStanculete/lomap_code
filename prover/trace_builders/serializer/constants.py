
# Trace Constants
TRACE_WIDTH         = 399
REGISTER_LIMIT      = pow(2, 64)

OPERATION_CODES = {
    "PaddingWithCounter": (0, 1),
    "PaddingWithoutCounter": (0, 2),

    "HeaderSerialization": (1, 0),
    "FieldSerialization": (1, 1),
    "AccumulatorUpdate": (1, 2),
    "AccumulatorLeftAllignment": (1, 3),
    "AccumulatorRightAllignment": (1, 4),
    "PostHashBookkeeping": (1, 5),

    "HashInputRow": (2, 0),
    "HashFirstHalfRound": (2, 1),
    "HashSecondHalfRound": (2, 2),
    "HashScheduleUpdate": (2, 3),
    "HashAggregation": (2, 4),
    "HashCleanup": (2, 5),

    "SignatureVerifInput": (3, 0),
    "SignatureVerifMulti": (3, 1),
    "SignatureVerifRed": (3, 2),
    "SignatureVerifAttest": (3, 3)
}

FIELD_MODULUS = pow(2, 128) - 45 * pow(2, 40) + 1

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