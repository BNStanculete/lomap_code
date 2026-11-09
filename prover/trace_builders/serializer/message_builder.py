from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.poseidon import PoseidonTraceBuilder
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from prover.trace_builders.sha256.constants import ROUND_CONSTANTS
from prover.trace_builders.utils import FIELD_MODULUS

from . import constants

class MessageTraceBuilder(TraceBuilder):
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

        self.__OPBITS = constants.OPERATION_CODES["HashInputRow"]
        self.__NUM_ROWS = 0


    def build_trace(self, in_memory):
        trace = Trace()

        # The input row coincides with the first row of hashing
        # self.__build_row(trace, in_memory)
        # self.__NUM_ROWS += 1

        # 1) Perform a SHA-256 Hashing
        HASH_REGISTERS = RegisterView(
            (self.__REMAINING, 0, 285)
        )

        self.__hasher.from_message(self.__input_data["Message"].encode('utf-8'))
        hash_trace = self.__hasher.build_trace(True)

        # We write the SHA-256 subtrace
        r_index = 0
        for row in hash_trace.as_list():
            r_index %= 64
            relative_row = row[0] % 177
            
            self.__HASH_CONSTANT = 0
            for col in range(1, len(row)):
                HASH_REGISTERS[col - 1] = row[col]

            if relative_row == 0:
                self.__OPBITS = constants.OPERATION_CODES["HashAggregation"]
            elif (relative_row < 32 and (relative_row) % 2 == 1) or (relative_row >= 32 and (relative_row) % 3 == 1):
                self.__OPBITS = constants.OPERATION_CODES["HashFirstHalfRound"]
                self.__HASH_CONSTANT = ROUND_CONSTANTS[r_index]
            elif (relative_row < 32 and (relative_row) % 2 == 0) or (relative_row >= 32 and (relative_row) % 3 == 2):
                self.__OPBITS = constants.OPERATION_CODES["HashSecondHalfRound"]
                r_index += 1
            elif relative_row >= 32 and (relative_row) % 3 == 0:
                self.__OPBITS = constants.OPERATION_CODES["HashScheduleUpdate"]
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

        # We extract the final hash, and reset the registers
        self.__OPBITS = constants.OPERATION_CODES["HashCleanup"]

        for idx in range(4):
            self.__HASH[3 - idx] = ((HASH_REGISTERS[266 - 2* idx] << 32) | HASH_REGISTERS[267 - 2* idx])

        for idx in range(SHA_TRACE_WIDTH - 1):
            HASH_REGISTERS[idx] = 0

        # For Poseidon
        HASH_REGISTERS[162] = 1
        HASH_REGISTERS[163] = 1

        self.__build_row(trace, in_memory)
        self.__NUM_ROWS += 1

        # Now we compute the Poseidon hash of the public key
        poseidon_blocks = []
        for i in range(18):
            poseidon_blocks.append(self.__PUBLIC_KEY[2*i] << 64 | self.__PUBLIC_KEY[2*i+1])
        self.__poseidon.set_blocks(poseidon_blocks)
        poseidon_trace = self.__poseidon.build_trace(True)
        poseidon_trace = poseidon_trace.as_list()

        # Now we extract the poseidon trace
        # We compress 26 Poseidon rounds into 1 row
        POSEIDON_REGISTERS = RegisterView(
            (self.__REMAINING, 0, 312)
        )

        row_index = 0
        pub_key_index = 1
        while row_index < len(poseidon_trace):
            if row_index % 91 == 0:
                self.__OPBITS = constants.OPERATION_CODES["PoseidonInput"]
            elif row_index % 91 == 78:
                self.__OPBITS = constants.OPERATION_CODES["PoseidonOutput"]
            else:
                self.__OPBITS = constants.OPERATION_CODES["PoseidonRound"]

            for set in range(26):
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

                    for i in range(set * 12 + 18, 312):
                        POSEIDON_REGISTERS[i] = 0

                    assert 312 - 18 - set * 12 > 18, "Not enough bits for PUB_KEY selector"

                    # Now we set the bits.
                    if pub_key_index < 9:
                        POSEIDON_REGISTERS[set * 12 + 18 + 2 * pub_key_index] = 1
                        POSEIDON_REGISTERS[set * 12 + 18 + 2 * pub_key_index + 1] = 1
                        pub_key_index += 1

                    # And we copy the digest
                    self.__POSEIDON_HASH[0] = row_output[0] >> 128
                    self.__POSEIDON_HASH[1] = row_output[0] & ((1 << 128) - 1)

                    self.__build_row(trace, in_memory)
                    self.__NUM_ROWS += 1
                    row_index += 1
                    break

                row_index += 1
            else:
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1

        # Now we perform a signature verification
        signature, representative, pub_key = self.__get_signature_params()
        self.__signature_verifier.set_input(representative, pub_key, signature)

        signature_trace = self.__signature_verifier.build_trace(True)
        self.__write_signature_trace(signature_trace, trace, in_memory)

        # Finally we pad to a power of two.
        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)

        # Clear Poseidon
        self.__poseidon.start_new_trace()

        return trace

    def __pad_rows(self, trace, in_memory):
        self.__OPBITS = constants.OPERATION_CODES["PaddingWithoutCounter"]
        target_rows = next_power_of_two(self.__NUM_ROWS)

        for _ in range(self.__NUM_ROWS, target_rows):
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

    def __parse_signature_and_key(self):
        signature_oid = self.__input_data["SignatureAlgorithm"]
        public_key = self.__input_data["PublicKey"]
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

    def __write_signature_trace(self, signature_trace, trace, in_memory):
        SIGNATURE_REGISTERS = RegisterView(
            (self.__REMAINING, 0, 320)
        )

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

    def __reset_registers(self):
        self.__NUM_ROWS = 0
        self.__OPBITS = [0] * 5

        # This encodes the input data for the signature verification
        self.__SIGNATURE_ALGO = 0
        self.__PUBLIC_KEY = [0] * 36
        self.__SIGNATURE = [0] * 32
        self.__HASH = [0] * 4
        self.__HASH_CONSTANT = 0
        self.__POSEIDON_HASH = [0] * 2

        # Additional registers according to the RSA-2048 builder
        self.__REMAINING = [0] * 320

    def __build_registers(self):
        return [
            self.__NUM_ROWS,
            *self.__OPBITS,
            *self.__PUBLIC_KEY,
            *self.__SIGNATURE,
            *self.__HASH,
            self.__HASH_CONSTANT,
            self.__SIGNATURE_ALGO,
            *self.__REMAINING,
            *self.__POSEIDON_HASH
        ]

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

        self.__poseidon = PoseidonTraceBuilder(trace_file)
        self.__poseidon.togglePadding()

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
