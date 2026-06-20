from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two, get_modular_inverse
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from prover.trace_builders.sha256.constants import ROUND_CONSTANTS
from prover.trace_builders.utils import FIELD_MODULUS

from ast import literal_eval

from . import constants
from . import utils

from functools import partial
from collections.abc import Callable

class CrlTraceBuilder(TraceBuilder):
    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def set_input(self, input_data: dict):
        self.__input_data = input_data
        self.__reset_registers()
        self.__parse_signature_and_key()
        self.__parse_serial()

    def build_trace(self, in_memory):
        trace = Trace()

        # Build the input row
        self.__build_row(trace, in_memory)

        # 1) We set the TBSCertList Header
        self.__conditional_serialize([
            partial(self.__set_tbs_length),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        # 2) We set the CRL Version
        self.__conditional_serialize([
            partial(self.__set_header, constants.INTEGER, 1, True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_version_value),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        # 3) We set the signature algorithm
        if self.__SIGNATURE_ALGO == 1:
            self.__conditional_serialize([
                partial(self.__set_header, constants.SEQUENCE, 13, True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.OID, 9),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_signature_oid_value),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.NULL, 0),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        # 4) We encode the issuer now
        self.__conditional_serialize([
            partial(self.__set_header, constants.SEQUENCE, self.__input_data["CRLFields"]["IssuerLength"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        for pair in self.__input_data["CRLFields"]["Issuer"]:
            (_, oid), (_, value), (_, length), (_, sublength) = pair.items()

            self.__conditional_serialize([
                partial(self.__set_header, constants.SET, length),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.SEQUENCE, sublength),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_oid_header, oid),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_oid_value, oid),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.UTF8_STRING, len(value)),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_string_value, value),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

        # 5) We now encode the time interval fields
        self.__conditional_serialize([
            partial(self.__set_header, constants.UTC_TIME, len(self.__input_data["CRLFields"]["ThisUpdate"]), True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_string_value, self.__input_data["CRLFields"]["ThisUpdate"]),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory),
        ], trace, in_memory)

        if "NextUpdate" in self.__input_data["CRLFields"].keys():
            self.__conditional_serialize([
                partial(self.__set_header, constants.UTC_TIME, len(self.__input_data["CRLFields"]["NextUpdate"]), True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_string_value, self.__input_data["CRLFields"]["NextUpdate"]),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

        # 6) We encode the revoked serials
        self.__conditional_serialize([
            partial(self.__set_header, constants.SEQUENCE, self.__input_data["CRLFields"]["RevokedLength"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory),
        ], trace, in_memory)

        for revoked_item in self.__input_data["CRLFields"]["RevokedSerials"]:
            (_, serial), (_, time), (_, length) = revoked_item.items()
            copy = serial
            byte_counter = 0

            while copy > 0:
                byte_counter += 1
                copy >>= 8

            self.__conditional_serialize([
                partial(self.__set_header, constants.SEQUENCE, length),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.INTEGER, byte_counter),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_revoked_serial, serial),         
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

            self.__conditional_serialize([
                partial(self.__set_header, constants.UTC_TIME, len(time)),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_string_value, time),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

        # 7) We write the CRL extensions and the 0x80 byte of the SHA-256 padding
        ext_bytes = literal_eval(self.__input_data["CRLFields"]["Extensions"])
        ext_bytes += 0x80.to_bytes(1)
        
        for byte in ext_bytes:
            if self.__CRL_LENGTH == 0:
                self.__CRL_END = 1
                self.__CRL_FIELD += 1

            self.__NUM_ROWS += 1
            self.__OPBITS = constants.OPERATION_CODES["HeaderSerialization"]
            self.__CRL_FIELD += 1

            self.__FIELD_LENGTH = 1
            self.__FIELD_VALUE[0] = byte
            self.__do_book_keeping()

            self.__conditional_serialize([
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        # 8) We set the hash padding and perform 1 more round
        self.__conditional_serialize([
            partial(self.__complete_padding, self.__input_data["CRLFields"]["TBSLength"]),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)
        self.__execute_hash_round(trace, in_memory)

        signature, representative, pub_key = self.__get_signature_params()
        self.__signature_verifier.set_input(representative, pub_key, signature)

        signature_trace = self.__signature_verifier.build_trace(True)
        self.__write_signature_trace(signature_trace, trace, in_memory)

        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)

    def __write_signature_trace(self, signature_trace, trace, in_memory):
        Placeholder = [0] * 4

        SIGNATURE_REGISTERS = RegisterView(
            (Placeholder, 0, 4),
            (self.__SERIAL, 0, 4),
            (self.__ACCUMULATORS, 0, 96),
            (self.__FIELD_VALUE, 0, 32),
            (self.__ATTESTORS, 0, 64),
            (self.__REVOCATORS, 0, 64),
            (self.__SHA_TRIGGER, 0, 3),
            (self.__REMAINING, 0, 53)
        )

        for row in signature_trace.as_list():
            self.__NUM_ROWS += 1

            if row[0] == 1:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifInput"]
            elif row[0] % 256 in [2, 130]:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifMulti"]
            elif row[0] % 256 in [66, 194]:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifRed"]
            else:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifAttest"]

            for col in range(73, len(row)):
                SIGNATURE_REGISTERS[col - 73] = row[col]
            
            self.__CRL_FIELD, self.__CRL_END, self.__HASH_CONSTANT, self.__SIGNATURE_ALGO = Placeholder
            self.__build_row(trace, in_memory)

    def __get_signature_params(self):
        signature = 0
        repr = 0
        pub_key = [0, 0]

        for i in range(32):
            signature <<= 64
            signature |= self.__SIGNATURE[i]

            if i < 4:
                repr <<= 64
                repr |= self.__HASH[i]

            pub_key[1] <<= 64
            pub_key[1] |= self.__PUBLIC_KEY[i+4]
        for i in range(4):
            pub_key[0] <<= 64
            pub_key[0] |= self.__PUBLIC_KEY[i]

        return (signature, repr, pub_key)

    def __complete_padding(self, length: int):
        self.__NUM_ROWS += 1
        self.__OPBITS = constants.OPERATION_CODES["HeaderSerialization"]
        self.__CRL_FIELD += 1

        zero_count = (56 - ((length + 1) % 64)) % 64
        bit_length = length * 8

        len_in_bytes = 8
        for idx in range(len_in_bytes):
            self.__FIELD_VALUE[zero_count + len_in_bytes - idx - 1] = bit_length & 0xFF
            bit_length >>= 8
        
        self.__FIELD_LENGTH = zero_count + len_in_bytes
        self.__do_book_keeping()

    def __set_revoked_serial(self, serial: int):
        # First 4 revocators store the representation of the serial in 64-bits
        copy = serial
        
        for idx in range(3):
            self.__REVOCATORS[3 - idx] = copy & 0xFFFFFFFFFFFFFFFF
            copy >>= 64

        # Next 4 revocators store the inverse (if it exists)
        for idx in range(3):
            if self.__SERIAL[idx] != self.__REVOCATORS[idx]:
                inverse = get_modular_inverse(abs(self.__SERIAL[idx] - self.__REVOCATORS[idx]))

                if self.__SERIAL[idx] - self.__REVOCATORS[idx] < 0:
                    self.__REVOCATORS[4 + idx] = FIELD_MODULUS - inverse
                else:
                    self.__REVOCATORS[4 + idx] = inverse

        # Next 4 revocators store the binary equivalent
        for idx in range(3):
            self.__REVOCATORS[8 + idx] = (self.__REVOCATORS[4 + idx] * (self.__SERIAL[idx] - self.__REVOCATORS[idx])) % FIELD_MODULUS

        # We need to have 1, 2, 3 or 4 - 1s.
        self.__REVOCATORS[12] = sum(self.__REVOCATORS[8:12])
        self.__REVOCATORS[13] = self.__REVOCATORS[12] // 2
        self.__REVOCATORS[14] = self.__REVOCATORS[12] % 2
        self.__REVOCATORS[15] = self.__REVOCATORS[13] // 2
        self.__REVOCATORS[16] = self.__REVOCATORS[13] % 2
        self.__REVOCATORS[17] = self.__REVOCATORS[15] // 2
        self.__REVOCATORS[18] = self.__REVOCATORS[15] % 2
        self.__REVOCATORS[19] = self.__REVOCATORS[14] + self.__REVOCATORS[16] + self.__REVOCATORS[18]

        # Now we put the value in the field
        self.__OPBITS = constants.OPERATION_CODES["FieldSerialization"]
        self.__NUM_ROWS += 1

        copy = serial
        byte_counter = 0

        while copy > 0:
            byte_counter += 1
            copy >>= 8
        
        self.__FIELD_LENGTH = byte_counter
        
        for idx in range(byte_counter):
            self.__FIELD_VALUE[byte_counter - idx - 1] = serial & 0xFF
            serial >>= 8
        self.__do_book_keeping()
        

    def __set_string_value(self, value: str):
        self.__OPBITS = constants.OPERATION_CODES["FieldSerialization"]
        self.__NUM_ROWS += 1
        self.__FIELD_LENGTH = len(value)

        for idx in range(len(value)):
            self.__FIELD_VALUE[idx] = int.from_bytes(value[idx].encode('utf-8'))
        self.__do_book_keeping()

    def __set_oid_value(self, oid: str):
        number = int(utils.OID2Hex(constants.OIDs[oid]), 16)
        byte_counter = 0
        copy = number

        while copy > 0:
            byte_counter += 1
            copy >>= 8

        self.__NUM_ROWS += 1
        self.__OPBITS = constants.OPERATION_CODES["FieldSerialization"]
        self.__FIELD_LENGTH = byte_counter

        for idx in range(byte_counter):
            self.__FIELD_VALUE[byte_counter - idx - 1] = number & 0xFF
            number >>= 8
        self.__do_book_keeping()

    def __set_oid_header(self, oid: str):
        number = int(utils.OID2Hex(constants.OIDs[oid]), 16)
        byte_counter = 0

        while number > 0:
            byte_counter += 1
            number >>= 8
        
        # Now we have the length of the OID
        self.__set_header(constants.OID, byte_counter)

    def __set_header(self, tag: int, length: int, new_field: bool = False):
        self.__OPBITS = constants.OPERATION_CODES["HeaderSerialization"]
        self.__NUM_ROWS += 1
        
        if new_field:
            self.__CRL_FIELD += 1
        
        tl = utils.BuildTL(tag, length)
        self.__FIELD_LENGTH = len(tl)
        
        for idx in range(len(tl)):
            self.__FIELD_VALUE[idx] = tl[idx]
        self.__do_book_keeping()

    def __set_signature_oid_value(self):
        self.__OPBITS = constants.OPERATION_CODES["FieldSerialization"]
        self.__NUM_ROWS += 1

        if self.__SIGNATURE_ALGO == 1:
            oid = utils.OID2Hex(constants.OIDs["SHA256_RSA"])
            oid = int(oid, 16)

            self.__FIELD_LENGTH = 9
            for idx in range(9):
                self.__FIELD_VALUE[8 - idx] = oid & 0xFF
                oid >>= 8 
            self.__do_book_keeping()

    def __set_version_value(self):
        self.__NUM_ROWS += 1
        self.__OPBITS = constants.OPERATION_CODES["FieldSerialization"]
        self.__FIELD_LENGTH = 1
        self.__FIELD_VALUE[0] = self.__input_data["CRLFields"]["Version"]
        self.__do_book_keeping()

    def __set_tbs_length(self):
        """Since its likely that the length of the CRL is multi-byte, we put the header as a regular field

        We also leave CRL_FIELD to 0, to mark that this is the TBS header, and not an actual field
        """
        length_tl = utils.BuildTL(constants.SEQUENCE, self.__input_data["CRLFields"]["TBSLength"])
        length = len(length_tl)
        length_tl = utils.BuildTL(constants.SEQUENCE, self.__input_data["CRLFields"]["TBSLength"] - length)

        self.__NUM_ROWS += 1
        self.__OPBITS = constants.OPERATION_CODES["HeaderSerialization"]
        self.__CRL_LENGTH = self.__input_data["CRLFields"]["TBSLength"]
        self.__FIELD_LENGTH = len(length_tl)

        for idx in range(len(length_tl)):
            self.__FIELD_VALUE[idx] = length_tl[idx]
        self.__do_book_keeping()

    def __parse_serial(self):
        serial = self.__input_data["ProverSerial"]

        for idx in range(4):
            self.__SERIAL[3 - idx] = serial & 0xFFFFFFFFFFFFFFFF
            serial >>= 64

    def __parse_signature_and_key(self):
        signature_oid = self.__input_data["CRLFields"]["SignatureAlgorithm"]
        public_key = self.__input_data["PublicKey"]
        signature = self.__input_data["CRLFields"]["Signature"]
        
        if signature_oid == constants.OIDs["SHA256_ECDSA"]:
            self.__SIGNATURE_ALGO = 2
            x, y = public_key

            for idx in range(4):
                self.__PUBLIC_KEY[3-idx] = x & 0xFFFFFFFFFFFFFFFF
                self.__PUBLIC_KEY[7-idx] = y & 0xFFFFFFFFFFFFFFFF
                x >>= 64
                y >>= 64

            r, s = signature
            for idx in range(4):
                self.__SIGNATURE[3-idx] = r & 0xFFFFFFFFFFFFFFFF
                self.__SIGNATURE[7-idx] = s & 0xFFFFFFFFFFFFFFFF
                r >>= 64
                s >>= 64
        elif signature_oid == constants.OIDs["SHA256_RSA"]:
            self.__SIGNATURE_ALGO = 1
            signature = signature[0]
            e, n = public_key

            for idx in range(4):
                self.__PUBLIC_KEY[3-idx] = e & 0xFFFFFFFFFFFFFFFF
                e >>= 64

            for idx in range(32):
                self.__SIGNATURE[31-idx] = signature & 0xFFFFFFFFFFFFFFFF
                self.__PUBLIC_KEY[35-idx] = n & 0xFFFFFFFFFFFFFFFF
                signature >>= 64
                n >>= 64
        else:
            self.__SIGNATURE_ALGO = 0

    def __init__(self, trace_file: str):
        self.__reset_registers()

        self.__raw = b''
        self.__trace_file = trace_file
        self.__hasPadding = True

        # Internal builders for hashing & signature verification
        self.__hasher = Sha256TraceBuilder(trace_file)
        self.__hasher.toggleAttestation()
        self.__hasher.togglePadding()

        self.__signature_verifier = RSA2048TraceBuilder(trace_file)
        self.__signature_verifier.togglePadding()

    def __conditional_serialize(self, serialization_steps: list[Callable[[], None]], trace, in_memory):
        if not self.__can_execute_hash_round():
            for serialization_step in serialization_steps:
                serialization_step()
        else:
            self.__execute_hash_round(trace, in_memory)

            # Now we resume with serialization
            for serialization_step in serialization_steps:
                serialization_step()

    def __execute_hash_round(self, trace, in_memory):
        # Invariant: FIELD_LENGTH == 0 && BYTE_COUNTER >= 64s
        # 1) Left-align the accumulators and pad to a multiple of 256 (preparation)
        self.__allign_accumulators(trace, in_memory, left=True)

        # 2) Combine accumulators into 4-byte blocks and extract hashes
        message_blocks = []
        for index in range(0, 64, 4):
            block = (self.__ACCUMULATORS[index] << 24)    |   \
                    (self.__ACCUMULATORS[index+1] << 16)  |   \
                    (self.__ACCUMULATORS[index+2] << 8)   |   \
                    (self.__ACCUMULATORS[index+3])
            message_blocks.append(block)
        
        hashes = []
        for index in range(4):
            hashes.append(self.__HASH[index] >> 32)
            hashes.append(self.__HASH[index] & 0xFFFFFFFF)
        
        # 3) Build the SHA-256 trace for this block
        self.__hasher.set_message_blocks(message_blocks, hashes)            
        hash_trace = self.__hasher.build_trace(True)

        # 4) Map registers for SHA-trace
        HASH_REGISTERS = RegisterView(
            (self.__ACCUMULATORS, 0, 64),
            (self.__FIELD_VALUE, 0, 32),
            (self.__ATTESTORS, 0, 64),
            (self.__REVOCATORS, 0, 64),
            (self.__REMAINING, 0, 45)
        )

        # 5) Start writing the SHA-trace
        r_index = 0
        for row in hash_trace.as_list():
            
            self.__HASH_CONSTANT = 0
            for col in range(1, len(row)):
                HASH_REGISTERS[col - 1] = row[col]

            self.__NUM_ROWS += 1
            if row[0] - 1 == 0:
                self.__OPBITS = constants.OPERATION_CODES["HashInputRow"]
            elif (row[0] - 1 < 32 and (row[0] - 1) % 2 == 0) or (row[0] - 1 >= 32 and row[0] - 1 < 177 and (row[0] - 1) % 3 == 0):
                self.__OPBITS = constants.OPERATION_CODES["HashFirstHalfRound"]
                self.__HASH_CONSTANT = ROUND_CONSTANTS[r_index]
                r_index += 1
            elif (row[0] - 1 < 32 and (row[0] - 1) % 2 == 1) or (row[0] - 1 >= 32 and row[0] - 1 < 177 and (row[0] - 1) % 3 == 1):
                self.__OPBITS = constants.OPERATION_CODES["HashSecondHalfRound"]
            elif row[0] - 1 >= 32 and row[0] - 1 < 177 and (row[0] - 1) % 3 == 2:
                self.__OPBITS = constants.OPERATION_CODES["HashScheduleUpdate"]
            elif row[0] - 1 == 177:
                self.__OPBITS = constants.OPERATION_CODES["HashAggregation"]
            self.__build_row(trace, in_memory)

        # 6) We extract the output hash and reset the registers
        self.__OPBITS = constants.OPERATION_CODES["HashCleanup"]
        self.__NUM_ROWS += 1

        for idx in range(4):
            self.__HASH[3 - idx] = ((HASH_REGISTERS[266 - 2* idx] << 32) | HASH_REGISTERS[267 - 2* idx])

        for idx in range(SHA_TRACE_WIDTH):
            HASH_REGISTERS[idx] = 0
        self.__build_row(trace, in_memory)

        # 7) We reallign to the right
        self.__allign_accumulators(trace, in_memory, left=False)

        # 8) We update the byte_counter accordingly
        self.__OPBITS = constants.OPERATION_CODES["PostHashBookkeeping"]
        self.__NUM_ROWS += 1
        self.__BYTE_COUNTER -= 64
        self.__do_book_keeping()
        self.__build_row(trace, in_memory)

    def __write_value_encoding(self, trace: Trace, in_memory: bool):
        while self.__FIELD_LENGTH > 0:
            self.__update_accumulators()
            self.__build_row(trace, in_memory)

    def __update_accumulators(self):
        for idx in range(1, len(self.__ACCUMULATORS)):
            self.__ACCUMULATORS[idx - 1] = self.__ACCUMULATORS[idx]
        self.__ACCUMULATORS[-1] = self.__FIELD_VALUE[0]
        self.__raw += self.__FIELD_VALUE[0].to_bytes(1)

        for idx in range(1, len(self.__FIELD_VALUE)):
            self.__FIELD_VALUE[idx - 1] = self.__FIELD_VALUE[idx]
        self.__FIELD_VALUE[-1] = 0

        self.__FIELD_LENGTH -= 1
        self.__BYTE_COUNTER += 1
        self.__NUM_ROWS += 1

        if self.__CRL_LENGTH > 0:
            self.__CRL_LENGTH -= 1
        
        self.__do_book_keeping()

    def __pad_rows(self, trace, in_memory):
        self.__OPBITS = constants.OPERATION_CODES["PaddingWithoutCounter"]
        self.__NUM_ROWS += 1
        target_rows = next_power_of_two(self.__NUM_ROWS)

        for _ in range(self.__NUM_ROWS, target_rows):
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

    def __allign_accumulators(self, trace, in_memory, left: bool):
        if left:
            self.__OPBITS = constants.OPERATION_CODES["AccumulatorLeftAllignment"]
            self.__REMAINING[0] = self.__ALIGNMENT_COUNTER

            for _ in range(self.__ALIGNMENT_COUNTER):
                for i in range(1, len(self.__ACCUMULATORS)):
                    self.__ACCUMULATORS[i - 1] = self.__ACCUMULATORS[i]
                self.__ACCUMULATORS[-1] = 0
                self.__NUM_ROWS += 1
                self.__REMAINING[0] -= 1
                self.__do_book_keeping()
                self.__build_row(trace, in_memory)
        else:
            self.__OPBITS = constants.OPERATION_CODES["AccumulatorRightAllignment"]
            self.__REMAINING[0] = self.__ALIGNMENT_COUNTER

            for _ in range(self.__ALIGNMENT_COUNTER):
                for i in range(1, len(self.__ACCUMULATORS)):
                    self.__ACCUMULATORS[len(self.__ACCUMULATORS) - i] = self.__ACCUMULATORS[len(self.__ACCUMULATORS) - i - 1]
                self.__ACCUMULATORS[0] = 0
                self.__NUM_ROWS += 1
                self.__REMAINING[0] -= 1
                self.__do_book_keeping()
                self.__build_row(trace, in_memory)

    def __do_book_keeping(self):
        # Update attestors
        for idx in range(32):
            self.__ATTESTORS[2 * idx]       = self.__FIELD_VALUE[idx] // 256
            self.__ATTESTORS[2 * idx + 1]   = self.__FIELD_VALUE[idx] % 256

        # Update sha trigger
        self.__SHA_TRIGGER[0] = self.__BYTE_COUNTER // 64
        self.__SHA_TRIGGER[1] = self.__BYTE_COUNTER % 64

        # Constraints: self.__FIELD_LENGTH * self.__SHA_TRIGGER[2] = 0
        #              (1 - self.__SHA_TRIGGER[0]) * self.__SHA_TRIGGER[2] = 0
        if self.__SHA_TRIGGER[0] == 0 or self.__FIELD_LENGTH > 0:
            self.__SHA_TRIGGER[2] = 0
        else:
            self.__SHA_TRIGGER[2] = 1

        # Update allignment counter
        self.__ALIGNMENT_COUNTER = len(self.__ACCUMULATORS) - self.__BYTE_COUNTER

        # Break down the CRLField
        copy = self.__CRL_FIELD
        for i in range(1, 6):
            self.__REMAINING[6 - i] = copy % 2
            self.__REMAINING[11 - i] = self.__REMAINING[6 - i] * (1 - self.__OPBITS[0]) *   \
                                                                 (self.__OPBITS[1])     *   \
                                                                 (1 - self.__OPBITS[2]) *   \
                                                                 (1 - self.__OPBITS[3]) *   \
                                                                 (self.__OPBITS[4])
            copy //= 2

    def __can_execute_hash_round(self):
        return self.__SHA_TRIGGER[2]

    def __reset_registers(self):
        self.__NUM_ROWS = 0

        # This encodes the exact field we're serializing and guards transitions between opcodes
        self.__OPBITS = [0] * 5
        self.__CRL_FIELD = 0
        self.__CRL_END = 0

        self.__HASH_CONSTANT = 0

        # This encodes the input data for the CRL
        self.__SIGNATURE_ALGO = 0
        self.__SERIAL = [0] * 4
        self.__PUBLIC_KEY = [0] * 36
        self.__SIGNATURE = [0] * 32

        # 318 remaining registers that are safe to repurpose
        self.__HASH = [0] * 4
        self.__ACCUMULATORS = [0] * 96
        self.__FIELD_VALUE = [0] * 32

        self.__ATTESTORS = [0] * 64
        self.__REVOCATORS = [0] * 64
        self.__SHA_TRIGGER = [0] * 3
        self.__REMAINING = [0] * 53    

        # Loop counters
        self.__FIELD_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__BYTE_COUNTER = 0
        self.__ALIGNMENT_COUNTER = len(self.__ACCUMULATORS)

    def __build_registers(self):
        return [
            self.__NUM_ROWS,            #   S   H   V
            *self.__OPBITS,
            self.__CRL_FIELD,
            self.__CRL_END,             #   S
            self.__HASH_CONSTANT,       #   S
            self.__SIGNATURE_ALGO,      #   S
            *self.__SERIAL,             #   S
            *self.__PUBLIC_KEY,         #   S   H   V
            *self.__SIGNATURE,          #   S
            self.__FIELD_LENGTH,        #   S
            self.__CRL_LENGTH,          #   S
            self.__BYTE_COUNTER,        #   S
            self.__ALIGNMENT_COUNTER,   #   S
            *self.__HASH,               #   S
            *self.__ACCUMULATORS,       #   S
            *self.__FIELD_VALUE,        #   S
            *self.__ATTESTORS,          #   S
            *self.__REVOCATORS,
            *self.__SHA_TRIGGER,        #   S
            *self.__REMAINING           #   S(0)
        ]
    
    def __build_row(self, trace: Trace, in_memory: bool):
        """Saves the next row of the trace.

        If the in_memory flag is False, the row is immediatelly written to file.

        Arguments:
            trace (Trace): The trace that is currently being built
            in_memory (bool): Flag which denotes whether to store the row to file or keep it in memory.
        """
        if not in_memory:
            trace_matrix = trace.as_list()

            if len(trace_matrix) == 1:
                trace_matrix[0] = self.__build_registers()
            else:
                trace_matrix.append(self.__build_registers())
            trace.write_row_to_file(0, self.__trace_file)
        else:
            trace.as_list().append(self.__build_registers())
