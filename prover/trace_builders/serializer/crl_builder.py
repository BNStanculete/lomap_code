from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.sha256.constants import INITIAL_HASHES
from . import constants
from copy import deepcopy
from math import ceil, log2

# I also need the raw bytes, so I need the path

class CrlTraceBuilder(TraceBuilder):
    def __init__(self, trace_file: str):
        # State Machine registers
        self.__NUM_ROWS = 0
        self.__SUBTRACE = 0             # 1 - SERIAL, 2 - HASH, 3 - SIGNATURE
        self.__SUBTRACE_STEP = 0

        self.__HASH_SUBTRACE = 0        # non-0 when SUBTRACE = 2
        self.__SERIAL_SUBTRACE = 0      # non-0 when SUBTRACE = 1
        self.__SIGNATURE_SUBTRACE = 0   # non-0 when SUBTRACE = 3

        # Input registers
        self.__SERIAL = [0] * 4
        self.__SIGNATURE_ALGO = 0
        self.__PUBLIC_KEY = [0] * 36
        self.__SIGNATURE = [0] * 32

        # Output registers
        self.__OUT_HASH = [0] * 4

        # Serialization registers
        self.__BLOCK_ACCUMULATORS = [0] * 9
        self.__HASH = [0] * 4

        self.__SEQUENCE_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__CRL_END = 0
        self.__CRL_FIELD = 0
        self.__FIELD_LENGTH = 0     # For sequences or otherwise multi-row fields

        # From here is safe to repurpose
        self.__FIELD_VALUE = [0] * 8   # 8 64-bit registers exhausts an empty accumulator
        self.__REMAINING = [0] * 383

        self.__raw = b''
        self.__trace_file = trace_file
        self.__hasPadding = True

        # Internal builders for hashing & signature verification
        self.__hasher = Sha256TraceBuilder(trace_file)
        self.__signature_verifier = RSA2048TraceBuilder(trace_file)

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def set_input(self, serial: int, signature_oid: str, signature: list[int], public_key: list[int, int], raw_bytes: bytes) -> None:
        """Resets the trace builder and initializes the registers to the provided input
        """
        self.__reset_registers()
        self.__raw = raw_bytes

        # Set output hashes to initial blocks
        for idx in range(4):
            self.__OUT_HASH[idx] = (INITIAL_HASHES[2 * idx] << 32) | INITIAL_HASHES[2 * idx + 1]
            self.__HASH[idx] = (INITIAL_HASHES[2 * idx] << 32) | INITIAL_HASHES[2 * idx + 1]

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

        # Setting state machine
        self.__SUBTRACE = 1
        self.__SERIAL_SUBTRACE = 2

    def build_trace(self, in_memory) -> Trace:
        """The state machine has the following steps:
            0. Input row
            1. Version field (Integer, 1,2,3)
            (Signature is skipped since it must match the Input SIGNATURE_ALGO)
            
            2. Issuer field (Name, it must fit within the registers)
                -> May span multiple rows for long names.
                -> For that reason we need a row counter.
        
            3. ThisUpdate (fixed length)
            4. NextUpdate (fixed legnth)

            5. revokedCertificates
                6. userCertificate -> here we also attest non-revocation
                7. revocationDate
                8. extensions
                    -> Thi may take multiple rows
        
            9. extensions

        * For extensions we do not care about semantics, and not serialize.
          The prover is asked to input DER-encoded bytes
        
        ** Whenever BLOCK_ACUMULATORS[16] != 0, we immediatelly perform 1 SHA-256 round
        *** Object_End must be set by prover, and BLOCK_ACUMULATORS are initialized to the TBSCertList header (TL fields)
        **** We expect at the end that CRL_LENGTH = 0

        ***** To decrese CRL_LENGTH, we must calculate the length of the serialized fields.
        ***** For that we provide for each register 0 or (inv) => constraint: REG * (REG * INV - 1) = 0 (64 regs + 128 regs for first non-zero + 1 for non-revocation)
                => LENGTH = BIT_LENGTH + SUM 64 * (REG * INV) (this is for 1 row. If register can span more rows, we ask prover to provide length => LENGTH = 0 at the end)

        ***** The last 2 subtraces are in order:
            - SHA-256 (last hash with padding)
            - SIGNATURE_VERIFICATION
        In particular during last hash_update, if Object_End = 1, then Subtrace = SIGNATURE_VERIFICATION.
        """
        trace = Trace()

        # Build the input row
        self.__build_row(trace, in_memory)

        # We start encoding field by field
        offset = self.__set_crl_header()
        self.__build_row(trace, in_memory)

        # We set the TBSCertList header
        self.__set_tbs_header(offset)
        self.__build_row(trace, in_memory)


        return trace
    
    def __set_crl_header(self) -> int:
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1
        
        # Set the total expected length
        if int(self.__raw[1]) > 128:
            len_in_bytes = int(self.__raw[1] & 0x7F)
        else:
            len_in_bytes = 0

        self.__FIELD_LENGTH = len(self.__raw) - (len_in_bytes + 2)
        self.__CRL_LENGTH = self.__FIELD_LENGTH

        tl = self.__build_tl(constants.SEQUENCE)

        # Currently we operate under the assumption that the whole TLV will fit in 512-bits (1 SHA-256 Block)
        index = 7
        while tl > 0:
            self.__FIELD_VALUE[index] = tl & 0xFFFFFFFFFFFFFFFF
            self.__BLOCK_ACCUMULATORS[index + 1] = tl & 0xFFFFFFFFFFFFFFFF
            tl >>= 64
            index -= 1
        
        return len_in_bytes + 2

    def __set_tbs_header(self, offset):
        self.__NUM_ROWS += 1
        self.__SUBTRACE_STEP += 1

        if int(self.__raw[offset+1]) > 128:
            len_in_bytes = int(self.__raw[offset+1] & 0x7F)
        else:
            len_in_bytes = 0

        if len_in_bytes != 0:
            tbs_length = int(self.__raw[offset+2:offset+2+len_in_bytes].hex(), 16)
        else:
            tbs_length = int(self.__raw[offset+1])

        self.__FIELD_LENGTH = tbs_length
        self.__CRL_LENGTH -= (2 + len_in_bytes)

        tl = self.__build_tl(constants.SEQUENCE)
        
        index = 7
        while tl > 0:
            self.__FIELD_VALUE[index] = tl & 0xFFFFFFFFFFFFFFFF
            tl >>= 64
            index -= 1

        # We add the TL header to the blocks
        for index in range(8,-1,-1):
            self.__BLOCK_ACCUMULATORS[index] += self.__FIELD_VALUE[index - 1] + self.__REMAINING[index + 1]
            self.__REMAINING[index] = self.__BLOCK_ACCUMULATORS[index] // 2**64
            self.__BLOCK_ACCUMULATORS[index] %= 2**64

    def __build_tl(self, tag: int) -> int:
        """Starting from a tag, constructs the TL header of a TLV field
        """
        tl = tag

        # Add the length
        if self.__FIELD_LENGTH < 128:
            tl <<= 8
            tl |= self.__FIELD_LENGTH
        else:
            nr_bytes = ceil(ceil(log2(self.__FIELD_LENGTH)) / 8)

            tl <<= 8
            tl |= (0x80 | nr_bytes)
            tl <<= (8 * nr_bytes)
            tl |= self.__FIELD_LENGTH
        return tl

    def __reset_registers(self):
        # State Machine registers
        self.__NUM_ROWS = 0
        self.__SUBTRACE = 0
        self.__SUBTRACE_STEP = 0

        self.__HASH_SUBTRACE = 0
        self.__SERIAL_SUBTRACE = 0
        self.__SIGNATURE_SUBTRACE = 0

        # Input registers
        self.__SERIAL = [0] * 4
        self.__SIGNATURE_ALGO = 0
        self.__PUBLIC_KEY = [0] * 36
        self.__SIGNATURE = [0] * 32
        
        # Serialization registers
        self.__BLOCK_ACCUMULATORS = [0] * 17
        self.__HASH = [0] * 4

        self.__SEQUENCE_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__CRL_END = 0
        self.__CRL_FIELD = 0
        self.__FIELD_LENGTH = 0     # For sequences or otherwise multi-row fields

        # Output registers
        self.__OUT_HASH = [0] * 4

        # From here is safe to repurpose
        self.__FIELD_VALUE = [0] * 32   # 32 64-bit registers exhausts an empty accumulator
        self.__REMAINING = [0] * 383

    def __build_registers(self) -> list[int]:
        """Converts the registers into a trace row.
        """
        return [
            self.__NUM_ROWS,
            self.__SUBTRACE,
            self.__SUBTRACE_STEP,
            self.__HASH_SUBTRACE, self.__SERIAL_SUBTRACE, self.__SIGNATURE_SUBTRACE,
            *self.__SERIAL,
            self.__SIGNATURE_ALGO,
            *self.__PUBLIC_KEY,
            *self.__SIGNATURE,
            *self.__OUT_HASH,
            *self.__BLOCK_ACCUMULATORS,
            *self.__HASH,
            self.__SEQUENCE_LENGTH,
            self.__CRL_LENGTH,
            self.__CRL_END,
            self.__CRL_FIELD,
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
