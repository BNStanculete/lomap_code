from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two, get_modular_inverse
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.sha256.constants import INITIAL_HASHES
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from . import constants
from . import utils
from copy import deepcopy

from hashlib import sha256

from functools import partial
from collections.abc import Callable

FIELD_MODULUS = pow(2, 128) - 45 * pow(2, 40) + 1

class CrlTraceBuilder(TraceBuilder):
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

        # for debug
        self.__reconstructed = b''

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def set_input(self, serial: int, signature_oid: str, signature: list[int], public_key: list[int, int], issuer: list[dict], interval: list[str, str], revocation_data: list[int, str], raw_bytes: bytes) -> None:
        """Resets the trace builder and initializes the registers to the provided input
        """
        self.__reset_registers()
        self.__raw = raw_bytes
        self.__issuer = issuer
        self.__interval = interval
        self.__revocation_data = revocation_data

        # Set output hashes to initial blocks
        self.__REPRESENTATIVE[0] = 0x0001FFFFFFFFFFFF

        for i in range(1, 25):
            self.__REPRESENTATIVE[i] = 0xFFFFFFFFFFFFFFFF

        self.__REPRESENTATIVE[25] = 0xFFFFFFFF00303130 
        self.__REPRESENTATIVE[26] = 0x4801650D06096086 
        self.__REPRESENTATIVE[27] = 0x0304020105000420

        for idx in range(4):
            self.__REPRESENTATIVE[28+idx] = (INITIAL_HASHES[2 * idx] << 32) | INITIAL_HASHES[2 * idx + 1]

        # Set Serial
        for idx in range(4):
            self.__SERIAL[3 - idx] = serial & 0xFFFFFFFFFFFFFFFF
            serial >>= 64

        # Set signature algorithm identifier & signature
        if signature_oid == "1.2.840.10045.4.3.2":
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
        elif signature_oid == "1.2.840.113549.1.1.11":
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

    def build_trace(self, in_memory) -> Trace:
        trace = Trace()

        # We start encoding field by field
        self.__reconstruct_crl_header()
        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, "Mismatch during CRL HEADER serialization"

        # # We set the TBSCertList header
        crl_length = self.__set_tbs_header()
        self.__build_row(trace, in_memory)
        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, "Mismatch during TBSCERTLIST HEADER serialization"

        # # 1. We encode the version
        self.__conditional_serialize([
            partial(self.__set_version, 1),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during VERSION serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"

        # 2. We encode the signature
        self.__conditional_serialize([
            partial(self.__set_signature_outer),
            partial(self.__build_row, trace, in_memory),
            partial(self.__set_signature_inner1),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory),
            partial(self.__set_signature_inner2),
            partial(self.__build_row, trace, in_memory)
        ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during SIGNATURE serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"
        assert self.__SEQUENCE_LENGTH == 0, f"{self.__SEQUENCE_LENGTH}"

        # 3. We encode the issuer
        self.__conditional_serialize([
            partial(self.__set_issuer_header),
            partial(self.__build_row, trace, in_memory),
        ], trace, in_memory)

        for pair in self.__issuer:
            (_, oid), (_, value) = pair.items()

            self.__conditional_serialize([
                partial(self.__set_issuer_header, True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__set_issuer_header),
                partial(self.__build_row, trace, in_memory),
                partial(self.__set_issuer_OID, oid),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
                partial(self.__set_issuer_value, value),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during ISSUER serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"
        assert self.__SEQUENCE_LENGTH == 0, f"{self.__SEQUENCE_LENGTH}"

        # 4. We encode the current_update field
        self.__conditional_serialize([
            partial(self.__set_time_field, self.__interval[0]),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during CURRENT_UPDATE serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"

        # 5. We encode the next_update field
        self.__conditional_serialize([
            partial(self.__set_time_field, self.__interval[1]),
            partial(self.__build_row, trace, in_memory),
            partial(self.__write_value_encoding, trace, in_memory)
        ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during CURRENT_UPDATE serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"

        # 6. We put the serials and perform non-revocation checks.
        seq_length = self.__set_revoked_header()
        self.__write_value_encoding(trace, in_memory)
        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during REVOKEDCERTIFICATES HEADER serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"

        self.__NUM_ROWS += 1
        self.__SERIAL_SUBTRACE += 1
        self.__SUBTRACE_STEP += 1
        self.__SEQUENCE_LENGTH = seq_length
        self.__build_row(trace, in_memory)

        for revoked_serial, revoked_time in self.__revocation_data:
            self.__conditional_serialize([
                partial(self.__set_revoked_cert_header),
                partial(self.__build_row, trace, in_memory),
                partial(self.__set_revoked_cert_serial, revoked_serial),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory),
            ], trace, in_memory)

            self.__conditional_serialize([
                partial(self.__set_time_field, revoked_time, True),
                partial(self.__build_row, trace, in_memory),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

            assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during REVOKEDCERTIFICATES serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed} @ {revoked_serial}"
        
        # 7. We put the extensions as raw DER
        self.__SERIAL_SUBTRACE += 1

        while self.__CRL_LENGTH > 0:
            self.__conditional_serialize([
                partial(self.__set_extensions),
                partial(self.__write_value_encoding, trace, in_memory)
            ], trace, in_memory)

        assert self.__raw[:len(self.__reconstructed)] == self.__reconstructed, f"Mismatch during EXTENSIONS serialization: {self.__raw[:len(self.__reconstructed)]} vs {self.__reconstructed}"

        # 8. We mark end of CRL
        self.__conditional_serialize([
            partial(self.__set_hash_padding1),
            partial(self.__write_value_encoding, trace, in_memory, False)
        ], trace, in_memory)

        self.__conditional_serialize([
            partial(self.__set_hash_padding2, crl_length),
            partial(self.__write_value_encoding, trace, in_memory, False)
        ], trace, in_memory)

        # 9. We peform the final hash round
        self.__execute_hash_round(trace, in_memory)

        out_hash = self.__REPRESENTATIVE[28:]
        digest = b"".join(w.to_bytes(8, "big") for w in out_hash)
        expected = sha256(self.__reconstructed[4:]).hexdigest()

        assert expected == digest.hex(), f"Mismatch in HASH"

        # 10. We do the signature verification
        signature = 0
        repr = 0
        pub_key = [0, 0]

        for i in range(32):
            signature <<= 64
            signature |= self.__SIGNATURE[i]

            repr <<= 64
            repr != self.__REPRESENTATIVE[i]

            pub_key[1] <<= 64
            pub_key[1] |= self.__PUBLIC_KEY[i+4]
        for i in range(4):
            pub_key[0] <<= 64
            pub_key[0] |= self.__PUBLIC_KEY[i]

        self.__signature_verifier.from_signed_message(repr, pub_key, signature)
        verif_trace = self.__signature_verifier.build_trace(True)

        reg_view = RegisterView(
            (self.__BLOCK_ACCUMULATORS, 0, 128),
            (self.__FIELD_VALUE, 0, 72),
            (self.__REMAINING, 0, 212)
        )

        self.__SUBTRACE = 3
        self.__SIGNATURE_SUBTRACE = 1
        self.__SUBTRACE_STEP = 0

        for row in verif_trace.as_list():
            self.__NUM_ROWS += 1
            
            for col in range(72, 393):
                reg_view[col - 72] = row[col]
            self.__build_row(trace, in_memory)

        completed_rows = self.__NUM_ROWS
        for _ in range(completed_rows, next_power_of_two(completed_rows)):
            self.__NUM_ROWS += 1
            self.__build_row(trace, in_memory)

        return trace
    
    def __conditional_serialize(self, serialization_steps: list[Callable[[], None]], trace, in_memory):
        if not self.__can_perform_hash_round():
            for serialization_step in serialization_steps:
                serialization_step()
        else:
            self.__execute_hash_round(trace, in_memory)

            # Now we resume with serialization
            self.__SUBTRACE_STEP = self.__SERIAL_SUBTRACE
            for serialization_step in serialization_steps:
                serialization_step()

    def __execute_hash_round(self, trace, in_memory):
        message = []
        hashes = []

        # Next we unpack the hashes
        for index in range(4):
            hashes.append(self.__REPRESENTATIVE[28+index] >> 32)
            hashes.append(self.__REPRESENTATIVE[28+index] & 0xFFFFFFFF)

        # Now we pad to a multiple of 256
        self.__SUBTRACE = 2
        self.__SUBTRACE_STEP = 0    # <-- This means we're padding before the actual trace
        self.__HASH_SUBTRACE = 1

        # First we shift left until BLOCK_COUNTER == 72 
        while self.__EXTRA_COUNTER != 0:
            for i in range(1, 128):
                self.__BLOCK_ACCUMULATORS[i - 1] = self.__BLOCK_ACCUMULATORS[i]
            self.__BLOCK_ACCUMULATORS[127] = 0
            self.__EXTRA_COUNTER -= 1
            self.__NUM_ROWS += 1
            self.__build_row(trace, in_memory)

        # while self.__NUM_ROWS % 256 != 0:
        #     self.__NUM_ROWS += 1
        #     self.__build_row(trace, in_memory)

        for index in range(0, 64, 4):
            block = (self.__BLOCK_ACCUMULATORS[index] << 24)    |   \
                    (self.__BLOCK_ACCUMULATORS[index+1] << 16)  |   \
                    (self.__BLOCK_ACCUMULATORS[index+2] << 8)   |   \
                    (self.__BLOCK_ACCUMULATORS[index+3])
            message.append(block)

        self.__hasher.set_message_blocks(message, hashes)            
        hash_trace = self.__hasher.build_trace(True)

        # We repurpose the first 64 registers (as those are consumed)
        for idx in range(64):
            self.__FIELD_VALUE[idx] = 0

        HASH_REGISTERS = RegisterView(
            (self.__FIELD_VALUE, 0, 64),
            (self.__REMAINING, 0, 205)
        )

        # Now we add the contents of the SHA trace
        for row in hash_trace.as_list():
            self.__NUM_ROWS += 1
            self.__SUBTRACE_STEP += 1
            
            for col_idx in range(len(row)):
                HASH_REGISTERS[col_idx] = row[col_idx]
            self.__build_row(trace, in_memory)

        # Cleanup : copy the hash, reset to zero, shift blocks
        for idx in range(4):
            self.__REPRESENTATIVE[31 - idx] = ((HASH_REGISTERS[267 - 2* idx] << 32) | HASH_REGISTERS[268 - 2* idx])
        for idx in range(SHA_TRACE_WIDTH):
            HASH_REGISTERS[idx] = 0

        for idx in range(64):
            self.__BLOCK_ACCUMULATORS[idx] = 0
        
        self.__NUM_ROWS += 1
        self.__SUBTRACE = 1
        self.__SUBTRACE_STEP = 0
        self.__build_row(trace, in_memory)

        # Reset the counter to its previous state (except the first 64 accumulators have been consumed)
        while self.__EXTRA_COUNTER + self.__BLOCK_COUNTER != 128:
            for i in range(127):
                self.__BLOCK_ACCUMULATORS[127 - i] = self.__BLOCK_ACCUMULATORS[126 - i]
            self.__BLOCK_ACCUMULATORS[0] = 0
            self.__NUM_ROWS += 1
            self.__EXTRA_COUNTER += 1
            self.__build_row(trace, in_memory)
        
        # Now we reset the block counter and the extra counter
        self.__BLOCK_COUNTER -= 64
        self.__EXTRA_COUNTER += 64
        self.__NUM_ROWS += 1
        self.__build_row(trace, in_memory)

    def __can_perform_hash_round(self) -> bool:
        return self.__BLOCK_ACCUMULATORS[63] != 0

    def __write_value_encoding(self, trace: Trace, in_memory: bool, update: bool = True):
        while self.__FIELD_LENGTH > 0:
            self.__update_accumulators_with_value_step(update)
            self.__build_row(trace, in_memory)

    def __update_accumulators_with_header(self, tag: int, length: int):
        for idx in range(1,128):
            self.__BLOCK_ACCUMULATORS[idx - 1] = self.__BLOCK_ACCUMULATORS[idx]        
        self.__BLOCK_ACCUMULATORS[127] = tag
        self.__reconstructed += tag.to_bytes(1)

        for idx in range(1,128):
            self.__BLOCK_ACCUMULATORS[idx - 1] = self.__BLOCK_ACCUMULATORS[idx]        
        self.__BLOCK_ACCUMULATORS[127] = length
        self.__reconstructed += length.to_bytes(1)

        self.__CRL_LENGTH -= 2
        self.__BLOCK_COUNTER += 2
        self.__EXTRA_COUNTER -= 2

    def __update_accumulators_with_value_step(self, update: bool = True):
        for idx in range(1, 128):
            self.__BLOCK_ACCUMULATORS[idx - 1] = self.__BLOCK_ACCUMULATORS[idx]
        
        self.__BLOCK_ACCUMULATORS[127] = self.__FIELD_VALUE[0]

        if update:
            self.__reconstructed += self.__FIELD_VALUE[0].to_bytes(1)

        for idx in range(1, 72):
            self.__FIELD_VALUE[idx - 1] = self.__FIELD_VALUE[idx]
        
        self.__FIELD_VALUE[71] = 0
        self.__FIELD_LENGTH -= 1
        self.__BLOCK_COUNTER += 1
        self.__EXTRA_COUNTER -= 1

        if update:
            self.__CRL_LENGTH -= 1
        self.__NUM_ROWS += 1

        if self.__SEQUENCE_LENGTH > 0:
            self.__SEQUENCE_LENGTH -= 1

    def __reconstruct_crl_header(self) -> int:
        # Reconstruct the CRL header, so that we may extract the TBS header

        # Set the total expected length
        if int(self.__raw[1]) > 128:
            len_in_bytes = int(self.__raw[1] & 0x7F)
        else:
            len_in_bytes = 0

        tl = utils.BuildTL(constants.SEQUENCE, len(self.__raw) - (len_in_bytes + 2))
        self.__reconstructed += tl.to_bytes(
            (tl.bit_length() + 7) // 8
        )

    def __set_tbs_header(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE = 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        offset = len(self.__reconstructed)
        if int(self.__raw[offset+1]) > 128:
            len_in_bytes = int(self.__raw[offset+1] & 0x7F)
        else:
            len_in_bytes = 0

        if len_in_bytes != 0:
            tbs_length = int(self.__raw[offset+2:offset+2+len_in_bytes].hex(), 16)
        else:
            tbs_length = int(self.__raw[offset+1])

        self.__CRL_LENGTH = tbs_length

        tl = utils.BuildTL(constants.SEQUENCE, tbs_length)
        self.__reconstructed += tl.to_bytes(
            (tl.bit_length() + 7) // 8
        )

        index = 127
        counter = 0

        # We set the TBS header. The only other header we expect to have length > 128 is the revoked list
        while tl > 0:
            self.__BLOCK_ACCUMULATORS[index] = tl & 0xFF
            tl >>= 8
            index -= 1
            counter += 1
            self.__BLOCK_COUNTER += 1
            self.__EXTRA_COUNTER -= 1
        return tbs_length + counter

    def __set_version(self, version: int):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        self.__FIELD_VALUE[0] = version
        self.__FIELD_LENGTH = 1
        self.__update_accumulators_with_header(constants.INTEGER, 1)

    def __set_signature_outer(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        if self.__SIGNATURE_ALGO == 1:
            self.__SEQUENCE_LENGTH = 13
            self.__update_accumulators_with_header(constants.SEQUENCE, 13)

    def __set_signature_inner1(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        if self.__SIGNATURE_ALGO == 1:
            oid = utils.OID2Hex(constants.OIDs["SHA256_RSA"])
            self.__FIELD_LENGTH = 9
            self.__SEQUENCE_LENGTH -= 2

            value = int(oid, 16)
            for idx in range(9):
                self.__FIELD_VALUE[8 - idx] = value & 0xFF
                value >>= 8 

            self.__update_accumulators_with_header(constants.OID, 9)

    def __set_signature_inner2(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        if self.__SIGNATURE_ALGO == 1:
            self.__SEQUENCE_LENGTH -= 2

            self.__update_accumulators_with_header(constants.NULL, 0)

    def __set_issuer_header(self, is_set: bool = False):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        tag = constants.SET if is_set else constants.SEQUENCE

        offset = len(self.__reconstructed) + 1
        issuer_len = self.__raw[offset]

        if self.__SEQUENCE_LENGTH == 0:
            self.__SEQUENCE_LENGTH = issuer_len
        else:
            self.__SEQUENCE_LENGTH -= 2

        self.__update_accumulators_with_header(tag, issuer_len)

    def __set_issuer_OID(self, oid: str):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        self.__SEQUENCE_LENGTH -= 2

        value = int(utils.OID2Hex(constants.OIDs[oid]), 16)

        if oid == "CN":
            self.__FIELD_LENGTH = 3

            for index in range(3):
                self.__FIELD_VALUE[2 - index] = value & 0xFF
                value >>= 8

            self.__update_accumulators_with_header(constants.OID, 3)

    def __set_issuer_value(self, issuer: str):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        self.__SEQUENCE_LENGTH -= 2
        self.__FIELD_LENGTH = len(issuer)

        for index in range(len(issuer)):
            self.__FIELD_VALUE[index] = int.from_bytes(issuer[index].encode('utf-8'))

        self.__update_accumulators_with_header(constants.UTF8_STRING, len(issuer))

    def __set_time_field(self, time: str, decrease_seq: bool = False):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        self.__FIELD_LENGTH = len(time)

        if decrease_seq:
            self.__SEQUENCE_LENGTH -= 2

        for index in range(len(time)):
            self.__FIELD_VALUE[index] = int.from_bytes(time[index].encode('utf-8'))

        self.__update_accumulators_with_header(constants.UTC_TIME, len(time))

    def __set_revoked_header(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        offset = len(self.__reconstructed)
        if int(self.__raw[offset+1]) > 128:
            len_in_bytes = int(self.__raw[offset+1] & 0x7F)
        else:
            len_in_bytes = 0

        if len_in_bytes != 0:
            seq_length = int(self.__raw[offset+2:offset+2+len_in_bytes].hex(), 16)
        else:
            seq_length = int(self.__raw[offset+1])

        # self.__CRL_LENGTH -= (2 + len_in_bytes)
        self.__FIELD_LENGTH = 2 + len_in_bytes

        tl = utils.BuildTL(constants.SEQUENCE, seq_length)

        index = 1 + len_in_bytes

        # We set the TBS header. The only other header we expect to have length > 128 is the revoked list
        while tl > 0:
            self.__FIELD_VALUE[index] = tl & 0xFF
            tl >>= 8
            index -= 1

        return seq_length

    def __set_revoked_cert_header(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        offset = len(self.__reconstructed)
        seq_length = int(self.__raw[offset+1])

        self.__SEQUENCE_LENGTH -= 2
        self.__update_accumulators_with_header(constants.SEQUENCE, seq_length)

    def __set_revoked_cert_serial(self, serial: int):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1
        self.__SEQUENCE_LENGTH -= 2

        serial_length = (serial.bit_length() + 7) // 8
        self.__FIELD_LENGTH = serial_length
        
        # Proving non-revocation --- at least 1 register must have an inverse
        copy = serial
        for idx in range(4):
            self.__REMAINING[148 - idx] = serial & 0xFFFFFFFFFFFFFFFF
            diff = self.__SERIAL[3 - idx] - self.__REMAINING[148 - idx]

            if diff < 0:
                diff += FIELD_MODULUS

            if diff != 0:
                self.__REMAINING[152 - idx] = get_modular_inverse(diff, FIELD_MODULUS)
                self.__REMAINING[156 - idx] = diff * self.__REMAINING[152 - idx]        # This will be either 0 or 1

            serial >>= 64
        
        self.__REMAINING[157] = self.__REMAINING[156] + self.__REMAINING[155] + self.__REMAINING[154] + self.__REMAINING[153]
        
        self.__REMAINING[158] = self.__REMAINING[157] // 2      # 2  1  1  0
        self.__REMAINING[159] = self.__REMAINING[157] % 2       # 0  1  0  1

        self.__REMAINING[160] = self.__REMAINING[158] // 2      # 1  0  0  0
        self.__REMAINING[161] = self.__REMAINING[158] % 2       # 0  1  1  0

        self.__REMAINING[162] = self.__REMAINING[160] // 2      # 0  0  0  0
        self.__REMAINING[163] = self.__REMAINING[160] % 2       # 1  0  0  0

        # Constraint: this should be either 1 or 2
        self.__REMAINING[164] = self.__REMAINING[159] + self.__REMAINING[161] + self.__REMAINING[163]

        serial = copy
        for idx in range(serial_length):
            self.__FIELD_VALUE[serial_length - idx - 1] = serial & 0xFF
            serial >>= 8

        self.__update_accumulators_with_header(constants.INTEGER, serial_length)

    def __set_extensions(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1

        offset = len(self.__reconstructed)
        self.__FIELD_VALUE[0] = self.__raw[offset]
        self.__FIELD_LENGTH = 1

    def __set_hash_padding1(self):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        self.__FIELD_VALUE[0] = 0x80
        self.__FIELD_LENGTH = 1
    
    def __set_hash_padding2(self, length):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        self.__SERIAL_SUBTRACE += 1

        zero_count = (56 - ((length + 1) % 64)) % 64
        bit_length = length * 8

        len_in_bytes = 8
        for idx in range(len_in_bytes):
            self.__FIELD_VALUE[zero_count + len_in_bytes - idx - 1] = bit_length & 0xFF
            bit_length >>= 8
        
        self.__FIELD_LENGTH = zero_count + len_in_bytes

    def __reset_registers(self):
        # State Machine registers
        self.__NUM_ROWS = 0
        self.__SUBTRACE = 0
        self.__SUBTRACE_STEP = 0

        self.__HASH_SUBTRACE = 0
        self.__SERIAL_SUBTRACE = 0
        self.__SIGNATURE_SUBTRACE = 0
        self.__BLOCK_COUNTER = 0
        self.__EXTRA_COUNTER = 128

        # Input registers
        self.__SERIAL = [0] * 4
        self.__SIGNATURE_ALGO = 0
        self.__PUBLIC_KEY = [0] * 36
        self.__SIGNATURE = [0] * 32
        
        # Serialization registers
        self.__BLOCK_ACCUMULATORS = [0] * 128
        self.__REPRESENTATIVE = [0] * 32

        self.__SEQUENCE_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__CRL_END = 0
        self.__FIELD_LENGTH = 0

        # From here is safe to repurpose
        self.__FIELD_VALUE = [0] * 72
        self.__REMAINING = [0] * 212

    def __build_registers(self) -> list[int]:
        """Converts the registers into a trace row.
        """
        return [
            self.__NUM_ROWS,
            self.__SUBTRACE,
            self.__SUBTRACE_STEP,
            self.__HASH_SUBTRACE, self.__SERIAL_SUBTRACE, self.__SIGNATURE_SUBTRACE,
            self.__BLOCK_COUNTER, self.__EXTRA_COUNTER,
            *self.__SERIAL,
            self.__SIGNATURE_ALGO,
            *self.__PUBLIC_KEY,
            *self.__SIGNATURE,
            *self.__BLOCK_ACCUMULATORS,
            *self.__REPRESENTATIVE,
            self.__SEQUENCE_LENGTH,
            self.__CRL_LENGTH,
            self.__CRL_END,
            self.__FIELD_LENGTH,
            *self.__FIELD_VALUE,
            *self.__REMAINING,
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
