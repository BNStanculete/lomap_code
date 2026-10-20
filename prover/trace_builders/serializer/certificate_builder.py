from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.poseidon import PoseidonTraceBuilder
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from prover.trace_builders.sha256.constants import ROUND_CONSTANTS as SHA_ROUND_CONSTANTS
from prover.trace_builders.sha256.constants import INITIAL_HASHES as SHA_HASH_CONSTANTS

from ast import literal_eval

from . import constants
from . import utils

from functools import partial
from collections.abc import Callable

class CertificateTraceBuilder(TraceBuilder):
    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def setPadding(self, padding):
        self.__hasPadding = padding

    def set_input(self, input_data: dict):
        self.__input_data = input_data
        self.__reset_registers()
        self.__parse_signature_and_key()

        for i in range(4):
            self.__HASH[i] = (SHA_HASH_CONSTANTS[2 * i] << 32) | SHA_HASH_CONSTANTS[2 * i + 1]

    def build_trace(self, in_memory):
        trace = Trace()

        # Build the input row
        self.__build_row(trace, in_memory)
        self.__NUM_ROWS += 1

        # 1) We set the TBSCertList Header
        self.__conditional_serialize([
            partial(self.__set_tbs_length),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        # 2) We set the Certificate Version
        self.__conditional_serialize([
            partial(self.__set_header, constants.BRACKET_ZERO, 3, True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_header, constants.INTEGER, 1),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_version_value),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        # 3) We set the Certificate serial number --> goes in poseidon
        serial_bytes = (self.__input_data["Serial"].bit_length() + 7) // 8
        self.__conditional_serialize([
            partial(self.__set_header, constants.INTEGER, serial_bytes, True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_serial_number),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        # We now build a poseidon trace
        self.__build_poseidon_trace(trace, in_memory, self.__POSEIDON_INPUT)

        # 4) We set the signature algorithm
        if self.__SIGNATURE_ALGO == 1:
            self.__conditional_serialize([
                partial(self.__set_header, constants.SEQUENCE, 13, True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.OID, 9),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_signature_oid_value),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.NULL, 0),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        # 5) We encode the issuer now -- GOES IN POSEIDON
        self.__conditional_serialize([
            partial(self.__set_header, constants.SEQUENCE, self.__input_data["IssuerLength"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        for pair in self.__input_data["Issuer"][::-1]:
            (_, oid), (_, value), (_, length), (_, sublength) = pair.items()

            if oid != 'C':
                if oid == 'CN':        
                    self.__conditional_serialize([
                        partial(self.__set_header, constants.SET, length),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.SEQUENCE, sublength),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_header, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_value, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.UTF8_STRING, len(value)),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_string_value, value, True),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                    ], trace, in_memory)
                else:
                    self.__conditional_serialize([
                        partial(self.__set_header, constants.SET, length),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.SEQUENCE, sublength),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_header, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_value, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.UTF8_STRING, len(value)),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_string_value, value),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                    ], trace, in_memory)
            else:
                self.__conditional_serialize([
                    partial(self.__set_header, constants.SET, length),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_header, constants.SEQUENCE, sublength),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_oid_header, oid),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_oid_value, oid),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_header, constants.PRINTABLE_STRING, len(value)),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_string_value, value),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                ], trace, in_memory)

        # 5) We now encode the time interval fields -- Goes in Poseidon
        self.__conditional_serialize([
            partial(self.__set_header, constants.SEQUENCE, len(self.__input_data["NotBefore"]) + 
                                                           len(self.__input_data["NotAfter"]) + 4),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        self.__conditional_serialize([
            partial(self.__set_header, constants.UTC_TIME, len(self.__input_data["NotBefore"])),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_string_value, self.__input_data["NotBefore"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
        ], trace, in_memory)

        self.__build_poseidon_trace(trace, in_memory, self.__POSEIDON_INPUT)

        self.__conditional_serialize([
            partial(self.__set_header, constants.UTC_TIME, len(self.__input_data["NotAfter"])),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_string_value, self.__input_data["NotAfter"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory),
        ], trace, in_memory)

        # 6) We encode the subject now -- Goes in Poseidon
        self.__conditional_serialize([
            partial(self.__set_header, constants.SEQUENCE, self.__input_data["SubjectLength"], True),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        for pair in self.__input_data["Subject"][::-1]:
            (_, oid), (_, value), (_, length), (_, sublength) = pair.items()

            if oid != 'C':
                if oid == 'CN':        
                    self.__conditional_serialize([
                        partial(self.__set_header, constants.SET, length),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.SEQUENCE, sublength),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_header, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_value, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.UTF8_STRING, len(value)),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_string_value, value, True),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                    ], trace, in_memory)
                else:
                    self.__conditional_serialize([
                        partial(self.__set_header, constants.SET, length),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.SEQUENCE, sublength),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_header, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_oid_value, oid),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_header, constants.UTF8_STRING, len(value)),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                        partial(self.__set_string_value, value),
                        partial(self.__build_row, trace, in_memory),
                        partial(self.__increment_rows),
                        partial(self.__write_value_encoding, trace, in_memory),
                    ], trace, in_memory)
            else:
                self.__conditional_serialize([
                    partial(self.__set_header, constants.SET, length),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_header, constants.SEQUENCE, sublength),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_oid_header, oid),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_oid_value, oid),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_header, constants.PRINTABLE_STRING, len(value)),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                    partial(self.__set_string_value, value),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                ], trace, in_memory)

        self.__build_poseidon_trace(trace, in_memory, self.__POSEIDON_INPUT)

        # 8) We now encode the subject public key -- Goes in Poseidon TWICE
        if self.__SIGNATURE_ALGO == 1:
            self.__conditional_serialize([
                partial(self.__set_header, constants.SEQUENCE, 290, True),
                # partial(self.__add_NULL_byte),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.SEQUENCE, 13),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.OID, 9),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_pubkey_oid_value),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.NULL, 0),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

            self.__conditional_serialize([
                partial(self.__set_header, constants.BIT_STRING, 271, True),
                partial(self.__add_NULL_byte),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.SEQUENCE, 266),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_header, constants.INTEGER, 257),
                partial(self.__add_NULL_byte),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

            # Add the public key modulus byte by byte
            self.__CRL_FIELD += 1
            
            # Custom trigger for PubKey
            self.__pub_key_blocks = []
            self.__counter = 0

            for shift in range(2040, -1, -8):
                self.__conditional_serialize([
                    partial(self.__get_modulus_byte, shift),
                    partial(self.__build_row, trace, in_memory),
                    partial(self.__increment_rows),
                    partial(self.__write_value_encoding, trace, in_memory),
                ], trace, in_memory)

            self.__pub_key_blocks.reverse()
            self.__pub_key_blocks.insert(0, self.__input_data["PublicKey"][0])
            self.__pub_key_blocks.insert(0, 0)
            self.__pub_key_blocks.extend([1, 0])

            self.__conditional_serialize([
                partial(self.__set_header, constants.INTEGER, 3, True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_exponent),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

            self.__POSEIDON_INPUT_SELECTOR[0] = 1
            self.__POSEIDON_INPUT_SELECTOR[1] = 1
            self.__poseidon_hasher.start_new_trace()
            self.__build_poseidon_trace(trace, in_memory, self.__pub_key_blocks, True)

            self.__poseidon_hasher.start_new_trace()
            self.__poseidon_hasher.set_input_state(self.__latest_output)
            self.__POSEIDON_INPUT[0] = self.__POSEIDON_HASH[0]
            self.__POSEIDON_INPUT[1] = self.__POSEIDON_HASH[1]
            self.__POSEIDON_INPUT_SELECTOR[0] = 1
            self.__POSEIDON_INPUT_SELECTOR[1] = 1
            self.__build_poseidon_trace(trace, in_memory, self.__POSEIDON_INPUT)

            self.__POSEIDON_INPUT[0] = 1
            self.__POSEIDON_INPUT[1] = 0
            self.__POSEIDON_INPUT_SELECTOR[0] = 1
            self.__POSEIDON_INPUT_SELECTOR[1] = 1
            self.__build_poseidon_trace(trace, in_memory, self.__POSEIDON_INPUT)
            self.__poseidon_hasher.start_new_trace()

        # 7) We write the Certificate extensions and the 0x80 byte of the SHA-256 padding
        ext_bytes = literal_eval(self.__input_data["ExtensionsRaw"])
        ext_bytes += 0x80.to_bytes(1)
        
        for byte in ext_bytes:
            self.__conditional_serialize([
                partial(self.__write_extension_byte, byte),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        # 8) We set the hash padding and perform 1 more round
        self.__CRL_FIELD += 1
        for _ in range(self.__get_num_zeroes(self.__input_data["TBSLength"])):
            self.__conditional_serialize([
                partial(self.__add_zero),
                partial(self.__build_row, trace, in_memory),
                partial(self.__increment_rows),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

        self.__conditional_serialize([
            partial(self.__complete_padding, self.__input_data["TBSLength"]),
            partial(self.__build_row, trace, in_memory),
            partial(self.__increment_rows),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)
        self.__execute_hash_round(trace, in_memory)

        signature, representative, pub_key = self.__get_signature_params()
        self.__signature_verifier.set_input(representative, pub_key, signature)

        signature_trace = self.__signature_verifier.build_trace(True)
        self.__write_signature_trace(signature_trace, trace, in_memory)

        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)

        return trace

    def __build_poseidon_trace(self, trace, in_memory, blocks, control_input = False):
        self.__poseidon_blocks += len(blocks)

        POSEIDON_REGISTERS = RegisterView(
            (self.__ATTESTORS, 0, 64),
            (self.__REVOCATORS, 0, 64),
            (self.__REMAINING, 0, 64)
        )

        for i in range(192):
            POSEIDON_REGISTERS[i] = 0

        pub_key_index = 1
        for i in range(0, len(blocks), 2):
            self.__POSEIDON_INPUT[0] = blocks[i]
            self.__POSEIDON_INPUT[1] = blocks[i+1]
            self.__POSEIDON_INPUT_SELECTOR[0] = 1
            self.__POSEIDON_INPUT_SELECTOR[1] = 1

            self.__poseidon_hasher.absorb_block([blocks[i], blocks[i+1]])
            poseidon_trace = self.__poseidon_hasher.build_trace(True)
            poseidon_trace = poseidon_trace.as_list()

            row_index = 0
            while row_index < len(poseidon_trace):
                if row_index % 91 == 0:
                    self.__OPBITS = constants.OPERATION_CODES["PoseidonInput"]
                elif row_index % 91 == 80:
                    self.__OPBITS = constants.OPERATION_CODES["PoseidonOutput"]
                else:
                    self.__OPBITS = constants.OPERATION_CODES["PoseidonRound"]

                for set in range(16):
                    row_input = poseidon_trace[row_index][2:5]
                    row_constants = poseidon_trace[row_index][5:8]
                    row_output = poseidon_trace[row_index][8:]

                    # Now we decompose the input into 2 128-bit limbs
                    for i in range(3):
                        POSEIDON_REGISTERS[set * 12 + 2 * i] = row_input[i] >> 128
                        POSEIDON_REGISTERS[set * 12 + 2 * i + 1] = row_input[i] & ((1 << 128) - 1)

                    # Now we decompose the constants
                    for i in range(3):
                        POSEIDON_REGISTERS[set * 12 + 2 * i + 6] = row_constants[i] >> 128
                        POSEIDON_REGISTERS[set * 12 + 2 * i + 7] = row_constants[i] & ((1 << 128) - 1)

                    # After we process the last row of a hash we always break
                    if row_index % 91 == 90:
                        # Here we also write the output...
                        for i in range(3):
                            POSEIDON_REGISTERS[set * 12 + 2 * i + 12] = row_output[i] >> 128
                            POSEIDON_REGISTERS[set * 12 + 2 * i + 13] = row_output[i] & ((1 << 128) - 1)

                        for i in range(set * 12 + 18, 192):
                            POSEIDON_REGISTERS[i] = 0

                        # Now we set the bits.
                        if control_input and pub_key_index < 9:
                            assert 192 - 18 - set * 12 > 18, "Not enough bits for PUB_KEY selector"

                            POSEIDON_REGISTERS[set * 12 + 18 + 2 * pub_key_index] = 1
                            POSEIDON_REGISTERS[set * 12 + 18 + 2 * pub_key_index + 1] = 1
                            pub_key_index += 1

                        # And we copy the digest
                        self.__POSEIDON_HASH[0] = row_output[0] >> 128
                        self.__POSEIDON_HASH[1] = row_output[0] & ((1 << 128) - 1)

                        # We also preserve the output for later
                        self.__latest_output = row_output

                        self.__build_row(trace, in_memory)
                        self.__NUM_ROWS += 1
                        row_index += 1

                        self.__POSEIDON_INPUT_SELECTOR[0] = 0
                        self.__POSEIDON_INPUT_SELECTOR[1] = 0
                        self.__POSEIDON_INPUT[0] = 0
                        self.__POSEIDON_INPUT[1] = 0
                        
                        break

                    row_index += 1
                else:
                    self.__build_row(trace, in_memory)
                    self.__NUM_ROWS += 1

        for i in range(192):
            POSEIDON_REGISTERS[i] = 0

    def __increment_rows(self):
        self.__NUM_ROWS += 1

    def __write_extension_byte(self, byte):
        if self.__CRL_LENGTH == 0:
            self.__CRL_END = 1
            self.__CRL_FIELD += 1

        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__CRL_FIELD += 1

        self.__FIELD_LENGTH = 1
        self.__FIELD_VALUE[0] = byte
        self.__do_book_keeping()

    def __set_exponent(self):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__FIELD_LENGTH = 3

        # Optimized for the common 65537 exponent
        self.__FIELD_VALUE[0] = (self.__input_data["PublicKey"][0] >> 16) & 0xFF
        self.__FIELD_VALUE[1] = (self.__input_data["PublicKey"][0] >> 8) & 0xFF
        self.__FIELD_VALUE[2] = (self.__input_data["PublicKey"][0]) & 0xFF
        self.__do_book_keeping()

    def __get_modulus_byte(self, shift: int):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__FIELD_LENGTH = 1
        self.__FIELD_VALUE[0] = (self.__input_data["PublicKey"][1] >> shift) & 0xFF
        self.__do_book_keeping()

        # Update the latest block
        if self.__pub_key_blocks == [] or self.__counter == 16:
            self.__pub_key_blocks.insert(0, 0)
            self.__counter = 0

        self.__pub_key_blocks[0] <<= 8
        self.__pub_key_blocks[0] |= self.__FIELD_VALUE[0]
        self.__counter += 1

    def __add_NULL_byte(self):
        self.__FIELD_LENGTH += 1

    def __write_signature_trace(self, signature_trace, trace, in_memory):
        SIGNATURE_REGISTERS = RegisterView(
            (self.__ACCUMULATORS, 0, 96),
            (self.__FIELD_VALUE, 0, 32),
            (self.__ATTESTORS, 0, 64),
            (self.__REVOCATORS, 0, 64),
            (self.__REMAINING, 0, 64)
        )

        for i in range(len(SIGNATURE_REGISTERS)):
            SIGNATURE_REGISTERS[i] = 0

        for row in signature_trace.as_list():
            if row[0] == 0:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifInput"]
            elif (row[0] - 1) % 256 == 0:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifCondMulti"]
            elif (row[0] - 1) % 256 == 128:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifMulti"]
            elif (row[0] - 1) % 256 == 64:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifCondRed"]
            elif (row[0] - 1) % 256 == 192:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifRed"]
            elif (row[0] - 1) % 256 < 128 and (row[0] - 1) % 256 > 0 and row[74] == 0:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifPadding"]
            else:
                self.__OPBITS = constants.OPERATION_CODES["SignatureVerifAttest"]

            self.__PUBLIC_KEY[0] = row[37]
            self.__PUBLIC_KEY[1] = row[38]
            self.__PUBLIC_KEY[2] = row[39]
            self.__PUBLIC_KEY[3] = row[40]

            for i in range(32):
                self.__SIGNATURE[i] = row[41 + i]

            for col in range(73, len(row)):
                SIGNATURE_REGISTERS[col - 73] = row[col]
            
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

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

    def __add_zero(self):
        self.__FIELD_LENGTH = 1
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__do_book_keeping()

    def __get_num_zeroes(self, length: int):
        return (56 - ((length + 1) % 64)) % 64

    def __complete_padding(self, length: int):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__CRL_FIELD += 1

        bit_length = length * 8

        len_in_bytes = 8
        for idx in range(len_in_bytes):
            self.__FIELD_VALUE[len_in_bytes - idx - 1] = bit_length & 0xFF
            bit_length >>= 8
        
        self.__FIELD_LENGTH = len_in_bytes
        self.__do_book_keeping()        

    def __set_string_value(self, value: str, add_to_poseidon: bool = False):
        if add_to_poseidon:
            self.__OPBITS = constants.OPERATION_CODES["SerializationWithHash"]
        else:
            self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
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

        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
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
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        
        if new_field:
            self.__CRL_FIELD += 1
        
        tl = utils.BuildTL(tag, length)
        self.__FIELD_LENGTH = len(tl)
        
        for idx in range(len(tl)):
            self.__FIELD_VALUE[idx] = tl[idx]
        self.__do_book_keeping()

    def __set_signature_oid_value(self):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]

        if self.__SIGNATURE_ALGO == 1:
            oid = utils.OID2Hex(constants.OIDs["SHA256_RSA"])
            oid = int(oid, 16)

            self.__FIELD_LENGTH = 9
            for idx in range(9):
                self.__FIELD_VALUE[8 - idx] = oid & 0xFF
                oid >>= 8 
            self.__do_book_keeping()

    def __set_pubkey_oid_value(self):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]

        if self.__SIGNATURE_ALGO == 1:
            oid = utils.OID2Hex(constants.OIDs["RSA"])
            oid = int(oid, 16)

            self.__FIELD_LENGTH = 9
            for idx in range(9):
                self.__FIELD_VALUE[8 - idx] = oid & 0xFF
                oid >>= 8 
            self.__do_book_keeping()

    def __set_serial_number(self):
        self.__OPBITS = constants.OPERATION_CODES["SerializationWithHash"]
        self.__FIELD_LENGTH = (self.__input_data["Serial"].bit_length() + 7) // 8

        index = self.__FIELD_LENGTH - 1
        copy = self.__input_data["Serial"]
        while index > -1:
            self.__FIELD_VALUE[index] = copy & 0xFF
            copy >>= 8
            index -= 1

        self.__do_book_keeping()

    def __set_version_value(self):
        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__FIELD_LENGTH = 1
        self.__FIELD_VALUE[0] = self.__input_data["Version"]
        self.__do_book_keeping()

    def __set_tbs_length(self):
        """Since its likely that the length of the CRL is multi-byte, we put the header as a regular field

        We also leave CRL_FIELD to 0, to mark that this is the TBS header, and not an actual field
        """
        length_tl = utils.BuildTL(constants.SEQUENCE, self.__input_data["TBSLength"])
        length = len(length_tl)
        length_tl = utils.BuildTL(constants.SEQUENCE, self.__input_data["TBSLength"] - length)

        self.__OPBITS = constants.OPERATION_CODES["NormalSerialization"]
        self.__CRL_LENGTH = self.__input_data["TBSLength"]
        self.__FIELD_LENGTH = len(length_tl)

        for idx in range(len(length_tl)):
            self.__FIELD_VALUE[idx] = length_tl[idx]
        self.__do_book_keeping()

    def __parse_signature_and_key(self):
        signature_oid = self.__input_data["SignatureAlgorithm"]
        public_key = self.__input_data["IssuerPublicKey"]
        signature = self.__input_data["Signature"]
        
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
        self.__poseidon_blocks = 0

        # Internal builders for hashing & signature verification
        self.__hasher = Sha256TraceBuilder(trace_file)
        self.__hasher.toggleAttestation()
        self.__hasher.togglePadding()

        self.__signature_verifier = RSA2048TraceBuilder(trace_file)
        self.__signature_verifier.togglePadding()

        self.__poseidon_hasher = PoseidonTraceBuilder(trace_file)
        self.__poseidon_hasher.togglePadding()

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
        self.__allign_accumulators(trace, in_memory, left=False)

        # 2) Combine accumulators into 4-byte blocks and extract hashes
        message_blocks = []
        for index in range(95, 31, -4):
            block = (self.__ACCUMULATORS[index] << 24)    |   \
                    (self.__ACCUMULATORS[index-1] << 16)  |   \
                    (self.__ACCUMULATORS[index-2] << 8)   |   \
                    (self.__ACCUMULATORS[index-3])
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
            (self.__ACCUMULATORS, 32, 64),
            (self.__FIELD_VALUE, 0, 32),
            (self.__ATTESTORS, 0, 64),
            (self.__REVOCATORS, 0, 64),
            (self.__REMAINING, 0, 60)
        )

        # Clear the registers just in case
        for i in range(len(HASH_REGISTERS)):
            HASH_REGISTERS[i] = 0

        # 5) Start writing the SHA-trace
        r_index = 0
        for idx, row in enumerate(hash_trace.as_list()):
            r_index %= 64
            relative_row = row[0] % 177
            
            self.__HASH_CONSTANT = 0
            for col in range(1, len(row)):
                HASH_REGISTERS[col - 1] = row[col]

            if relative_row == 0:
                if row[0] != 0:
                    self.__OPBITS = constants.OPERATION_CODES["HashAggregation"]
                else:
                    self.__OPBITS = constants.OPERATION_CODES["HashInputRow"]
            elif (relative_row < 32 and (relative_row) % 2 == 1) or (relative_row >= 32 and (relative_row) % 3 == 1):
                self.__OPBITS = constants.OPERATION_CODES["HashFirstHalfRound"]
                self.__HASH_CONSTANT = SHA_ROUND_CONSTANTS[r_index]
            elif (relative_row < 32 and (relative_row) % 2 == 0) or (relative_row >= 32 and (relative_row) % 3 == 2):
                self.__OPBITS = constants.OPERATION_CODES["HashSecondHalfRound"]
                r_index += 1
            elif relative_row >= 32 and (relative_row) % 3 == 0:
                self.__OPBITS = constants.OPERATION_CODES["HashScheduleUpdate"]
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

        # 6) We extract the output hash and reset the registers
        self.__OPBITS = constants.OPERATION_CODES["HashCleanup"]

        for idx in range(4):
            self.__HASH[3 - idx] = ((HASH_REGISTERS[266 - 2* idx] << 32) | HASH_REGISTERS[267 - 2* idx])

        for idx in range(SHA_TRACE_WIDTH - 1):
            HASH_REGISTERS[idx] = 0
        self.__build_row(trace, in_memory)
        self.__NUM_ROWS += 1

        # 7) We reallign to the right
        self.__allign_accumulators(trace, in_memory, left=True)

        # 8) We update the byte_counter accordingly
        self.__OPBITS = constants.OPERATION_CODES["PostHashBookkeeping"]
        self.__BYTE_COUNTER -= 64
        self.__do_book_keeping()
        self.__build_row(trace, in_memory)
        self.__NUM_ROWS += 1

    def __write_value_encoding(self, trace: Trace, in_memory: bool):
        counter = self.__FIELD_LENGTH

        while self.__FIELD_LENGTH > 0:
            if self.__OPBITS == constants.OPERATION_CODES["SerializationWithHash"]:
                self.__POSEIDON_INPUT[self.__POSEIDON_INPUT_SELECTOR[0]] <<= 8
                self.__POSEIDON_INPUT[self.__POSEIDON_INPUT_SELECTOR[0]] |= self.__FIELD_VALUE[0]

                if counter > 16:
                    self.__POSEIDON_INPUT[0] = self.__POSEIDON_INPUT[1] // pow(2, 128)
                    self.__POSEIDON_INPUT[1] %= pow(2, 128)

            self.__update_accumulators()
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

        if self.__OPBITS == constants.OPERATION_CODES["SerializationWithHash"]:
            if self.__POSEIDON_INPUT_SELECTOR[0] == 0:
                self.__POSEIDON_INPUT_SELECTOR[0] = 1
            else:
                self.__POSEIDON_INPUT_SELECTOR[1] = 1

    def __update_accumulators(self):
        for idx in range(len(self.__ACCUMULATORS) - 1, 0, -1):
            self.__ACCUMULATORS[idx] = self.__ACCUMULATORS[idx - 1]

        self.__ACCUMULATORS[0] = self.__FIELD_VALUE[0]
        self.__raw += self.__FIELD_VALUE[0].to_bytes(1)

        for idx in range(1, len(self.__FIELD_VALUE)):
            self.__FIELD_VALUE[idx - 1] = self.__FIELD_VALUE[idx]
        self.__FIELD_VALUE[-1] = 0

        self.__FIELD_LENGTH -= 1
        self.__BYTE_COUNTER += 1

        if self.__CRL_LENGTH > 0:
            self.__CRL_LENGTH -= 1
        
        self.__do_book_keeping()

    def __pad_rows(self, trace, in_memory):
        self.__OPBITS = constants.OPERATION_CODES["PaddingWithoutCounter"]
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
                self.__REMAINING[0] -= 1
                self.__do_book_keeping()
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1
        else:
            self.__OPBITS = constants.OPERATION_CODES["AccumulatorRightAllignment"]
            self.__REMAINING[0] = self.__ALIGNMENT_COUNTER

            for _ in range(self.__ALIGNMENT_COUNTER):
                for i in range(1, len(self.__ACCUMULATORS)):
                    self.__ACCUMULATORS[len(self.__ACCUMULATORS) - i] = self.__ACCUMULATORS[len(self.__ACCUMULATORS) - i - 1]
                self.__ACCUMULATORS[0] = 0
                self.__REMAINING[0] -= 1
                self.__do_book_keeping()
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1

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
        self.__POSEIDON_HASH = [0] * 2
        self.__POSEIDON_INPUT = [0] * 2
        self.__POSEIDON_INPUT_SELECTOR = [0] * 2

        # 318 remaining registers that are safe to repurpose
        self.__HASH = [0] * 4
        self.__ACCUMULATORS = [0] * 96
        self.__FIELD_VALUE = [0] * 32

        self.__ATTESTORS = [0] * 64
        self.__REVOCATORS = [0] * 64
        self.__SHA_TRIGGER = [0] * 3
        self.__REMAINING = [0] * 65

        # Loop counters
        self.__FIELD_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__BYTE_COUNTER = 0
        self.__ALIGNMENT_COUNTER = len(self.__ACCUMULATORS)

        self.__poseidon_blocks = 0

    def __build_registers(self):
        mlist = [
            self.__NUM_ROWS,            #   S   H   V
            *self.__OPBITS,
            *self.__SERIAL,
            *self.__PUBLIC_KEY,
            *self.__SIGNATURE,
            *self.__HASH,
            self.__HASH_CONSTANT,

            self.__SIGNATURE_ALGO,      #   S
            self.__CRL_FIELD,
            self.__CRL_END,             #   S
            self.__FIELD_LENGTH,        #   S
            self.__CRL_LENGTH,          #   S
            self.__BYTE_COUNTER,        #   S
            self.__ALIGNMENT_COUNTER,   #   S
            *self.__SHA_TRIGGER,        #   S
            *self.__ACCUMULATORS,       #   S
            *self.__FIELD_VALUE,        #   S
            *self.__ATTESTORS,          #   S
            *self.__REVOCATORS,
            *self.__REMAINING,          #   S(0)
            *self.__POSEIDON_INPUT,
            *self.__POSEIDON_HASH,
            *self.__POSEIDON_INPUT_SELECTOR,
        ]

        idx = 0
        for item in mlist:
            assert item < pow(2, 128), f"Wrong @ {mlist[0]} / {idx}"
            idx += 1

        return mlist
    
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
