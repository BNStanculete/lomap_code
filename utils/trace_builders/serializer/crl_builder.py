from trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two
from trace_builders.rsa2048 import RSA2048TraceBuilder
from trace_builders.sha256 import Sha256TraceBuilder
from . import constants
from copy import deepcopy

class CrlTrace(Trace):
    def __init__(self):
        super().__init__()
        
        self.__width = 0
        self.__height = next_power_of_two(0)
        self.__trace = []        

    def get_length(self):
        return self.__height
    
    def get_width(self):
        return self.__width

    def as_list(self):
        return self.__trace

    def _write_row_to_file(self, row_id, file_path):
        with open(file_path, "a") as file:
            for value in self.__trace[row_id]:
                file.write(str(value))
                file.write(" ")
            file.write("\n")

    def _extend_vertically(self, trace):
        trace_matrix = trace.as_list()

        for row in trace_matrix:
            self.__trace.append(row)

    def _extend_horizontally(self, trace):
        trace_matrix = trace.as_list()

        for row_index in range(0, self.__height):
            self.__trace[row_index].extend(trace_matrix[row_index])

class CrlTraceBuilder(TraceBuilder):
    def __init__(self, trace_file: str):
        # State Machine registers
        self.__NUM_ROWS = 0
        self.__SUBTRACE = 0
        self.__SUBTRACE_STEP = 0

        # Input registers
        self.__SERIAL = [0] * 4
        self.__SIGNATURE_ALGO = 0
        self.__SIGNATURE = [0] * 32
        
        # Serialization registers
        self.__BLOCK_ACCUMULATORS = [0] * 17
        self.__HASH = [0] * 4

        self.__SEQUENCE_LENGTH = 0
        self.__CRL_LENGTH = 0
        self.__CRL_END = 0
        self.__CRL_FIELD = 0
        self.__FIELD_LENGTH = 0     # For sequences or otherwise multi-row fields

        # From here is safe to repurpose
        self.__FIELD_VALUE = [0] * 64   # 64 32-bit registers exhausts an empty accumulator
        self.__REMAINING = [0] * 351

        self.__trace_file = trace_file
        self.__hasPadding = True

        # Internal builders for hashing & signature verification
        self.__hasher = Sha256TraceBuilder()
        self.__signature_verifier = RSA2048TraceBuilder()

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

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

        trace = CrlTrace()

        return trace