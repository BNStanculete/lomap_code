from trace_builders import TraceBuilder, Trace, next_power_of_two
from . import constants, utils
from copy import deepcopy

class Sha256Trace(Trace):
    def __init__(self, num_blocks: int):
        super().__init__()
        
        self.__width = constants.TRACE_WIDTH
        self.__height = next_power_of_two(num_blocks * constants.CYCLE_LENGTH + 5)
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

class Sha256TraceBuilder(TraceBuilder):
    def __init__(self, message, trace_file: str):
        self.__message_blocks = utils.from_bytes_to_32bit_blocks(
            utils.as_padded_bytes(message))
        self.__num_blocks = len(self.__message_blocks) // 16
        self.__trace_file = trace_file

        self.__NUM_ROWS = 0
        self.__W = [0 for _ in range(16)]
        self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H, self.__T1, self.__T2 = 0,0,0,0,0,0,0,0,0,0
        self.__BITS = [0 for _ in range(224)]
        self.__BITWISE_OUTPUT = [0, 0]
        self.__hasAttestation = True
        self.__hasPadding = True

        # Carries 0 - 2 are allocated for T1/W computation
        # Carries 3     are allocated for E
        # Carries 4     are allocated for T2
        # Carries 5     are allocated for A
        self.__CARRY = [0 for _ in range(8)]
        self.__HASH = [0 for _ in range(8)]

    def toggleAttestation(self):
        """Toggles whether to include hash attestation in the trace.
        """
        self.__hasAttestation = not self.__hasAttestation

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def from_message_blocks(self, message_blocks: list[int]):
        """Reset the builder using message blocks
        """
        self.__message_blocks = message_blocks
        self.__num_blocks = len(self.__message_blocks) // 16

        self.__NUM_ROWS = 0
        self.__W = [0 for _ in range(16)]
        self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H, self.__T1, self.__T2 = 0,0,0,0,0,0,0,0,0,0
        self.__BITS = [0 for _ in range(224)]
        self.__BITWISE_OUTPUT = [0, 0]

        # Carries 0 - 2 are allocated for T1/W computation
        # Carries 3     are allocated for E
        # Carries 4     are allocated for T2
        # Carries 5     are allocated for A
        self.__CARRY = [0 for _ in range(8)]
        self.__HASH = [0 for _ in range(8)]

    def build_trace(self, in_memory) -> Trace:
        trace = Sha256Trace(self.__num_blocks)
        blocks_to_process = True

        # Set the initial row
        self.__set_input_row(True)
        self.__build_row(trace, in_memory)

        # Process the SHA-256 blocks
        while blocks_to_process:
            for round in range(16):
                self.__build_first_half_round(round)
                self.__build_row(trace, in_memory)

                self.__build_second_half_round()
                self.__build_row(trace, in_memory)

            for round in range(16, 64):
                self.__build_message_schedule()
                self.__build_row(trace, in_memory)

                self.__build_first_half_round(round)
                self.__build_row(trace, in_memory)

                self.__build_second_half_round()
                self.__build_row(trace, in_memory)
            self.__build_hash_update()
            self.__build_row(trace, in_memory)

            blocks_to_process = (len(self.__message_blocks) != 0)
            if blocks_to_process:
                self.__set_input_row()

        # Build the size attestation
        if self.__hasAttestation:
            self.__build_size_attestation(True)
            self.__build_row(trace, in_memory)

            for _ in range(3):
                self.__build_size_attestation()
                self.__build_row(trace, in_memory)

        # Pad to the nearest power of two
        if self.__hasPadding:
            completed_rows = (177 * self.__num_blocks + 5)
            for _ in range(completed_rows, next_power_of_two(completed_rows)):
                self.__build_row(trace, in_memory)

        return trace

    def __build_registers(self) -> list[int]:
        """Converts the registers into a trace row.
        """
        return [
            self.__NUM_ROWS,
            *self.__W,
            self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H, self.__T1, self.__T2,
            *self.__BITS,
            *self.__BITWISE_OUTPUT,
            *self.__CARRY,
            *self.__HASH
        ]

    def __set_input_row(self, is_first_row: bool = False):
        """Constructs a block-input row for the trace.

        Arguments:
            is_first_row (bool) : Denotes whether this is the very first row of the trace
                or just the next set of message blocks. Defaults to False.
        """
        if is_first_row:
            self.__NUM_ROWS = 1
            self.__HASH = deepcopy(constants.INITIAL_HASHES)
            self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H = deepcopy(constants.INITIAL_HASHES)
            self.__CARRY = [1 for _ in range(8)]

        # Copy the first 16 blocks in the W registers and shift the blocks to the left.
        self.__W = self.__message_blocks[:16]
        self.__message_blocks = self.__message_blocks[16:]

    def __build_row(self, trace: Sha256Trace, in_memory: bool):
        """Saves the next row of the trace.

        If the in_memory flag is False, the row is immediatelly written to file.

        Arguments:
            trace (Sha256Trace): The trace that is currently being built
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

    def __build_first_half_round(self, round: int):
        """Builds T1 and updates E,F,G,H
        
        Arguments:
            round (int) : The round index. Used in selecting the appropriate constant.
        """
        self.__NUM_ROWS += 1

        # The first 3 sets of BITS store the bitwise decomposition of e,f,g
        for index in range(32):
            self.__BITS[index] = (self.__E >> (31 - index)) & 1
            self.__BITS[32 + index] = (self.__F >> (31 - index)) & 1
            self.__BITS[64 + index] = (self.__G >> (31 - index)) & 1

        # Bits sets 4 and 5 store the decomposition of Sum1 and Chi while the last 2 act as carries
        for index in range(32):
            sum1 = self.__BITS[(index - 6) % 32] + self.__BITS[(index - 11) % 32] + self.__BITS[(index - 25) % 32]
            chi = self.__BITS[index] * self.__BITS[32 + index] + (1 - self.__BITS[index]) * self.__BITS[64 + index]

            self.__BITS[96 + index] = sum1 % 2
            self.__BITS[160 + index] = sum1 // 2

            self.__BITS[128 + index] = chi % 2
            self.__BITS[192 + index] = chi // 2
        
        # The bitwise output stores the 32-bit equivalent
        power = pow(2, 31)
        self.__BITWISE_OUTPUT[0] = 0
        self.__BITWISE_OUTPUT[1] = 0
        for index in range(32):
            self.__BITWISE_OUTPUT[0] += power * self.__BITS[96 + index]
            self.__BITWISE_OUTPUT[1] += power * self.__BITS[128 + index]
            power //= 2

        self.__T1 = self.__H + sum(self.__BITWISE_OUTPUT) + constants.ROUND_CONSTANTS[round]
        self.__T1 += self.__W[15] if round > 15 else self.__W[round]

        # Reset carries
        self.__CARRY[0] = 0
        self.__CARRY[1] = 0
        self.__CARRY[2] = 0
        self.__CARRY[3] = 0

        for index in range(3):
            if self.__T1 < constants.REGISTER_LIMIT:
                break

            self.__CARRY[index] = 1
            self.__T1 -= constants.REGISTER_LIMIT
        
        self.__H, self.__G, self.__F, self.__E = self.__G, self.__F, self.__E, (self.__D + self.__T1)

        if self.__E >= constants.REGISTER_LIMIT:
            self.__E -= constants.REGISTER_LIMIT
            self.__CARRY[3] = 1

    def __build_second_half_round(self):
        """Builds T2 and updates A,B,C,D
        """
        self.__NUM_ROWS += 1
        
        # The first 3 sets of BITS store the bitwise decomposition of a,b,c
        for index in range(32):
            self.__BITS[index] = (self.__A >> (31 - index)) & 1
            self.__BITS[32 + index] = (self.__B >> (31 - index)) & 1
            self.__BITS[64 + index] = (self.__C >> (31 - index)) & 1

        # Bit sets 4 and 5 store the bitwise decomposition of Sum0 and Maj while the last 2 act as carries
        for index in range(32):
            Sum0 = self.__BITS[(index - 2) % 32] + self.__BITS[(index - 13) % 32] + self.__BITS[(index - 22) % 32]
            Maj = self.__BITS[index] * self.__BITS[32 + index] + self.__BITS[index] * self.__BITS[64 + index] + self.__BITS[32 + index] * self.__BITS[64 + index]

            self.__BITS[96 + index] = Sum0 % 2
            self.__BITS[160 + index] = Sum0 // 2

            self.__BITS[128 + index] = Maj % 2
            self.__BITS[192 + index] = Maj // 2

        # Bitwise output stores the 32-bit equivalent
        power = pow(2, 31)
        self.__BITWISE_OUTPUT[0] = 0
        self.__BITWISE_OUTPUT[1] = 0
        for index in range(32):
            self.__BITWISE_OUTPUT[0] += power * self.__BITS[96 + index]
            self.__BITWISE_OUTPUT[1] += power * self.__BITS[128 + index]
            power //= 2

        # Reset carries
        self.__CARRY[4] = 0
        self.__CARRY[5] = 0

        self.__T2 = sum(self.__BITWISE_OUTPUT)        
        if self.__T2 > constants.REGISTER_LIMIT:
            self.__T2 -= constants.REGISTER_LIMIT
            self.__CARRY[4] = 1

        self.__D, self.__C, self.__B, self.__A = self.__C, self.__B, self.__A,(self.__T1 + self.__T2)

        if self.__A >= constants.REGISTER_LIMIT:
            self.__A -= constants.REGISTER_LIMIT
            self.__CARRY[5] = 1

    def __build_message_schedule(self):
        self.__NUM_ROWS += 1

        # Temporarily copy W[0] (W_t-16)
        W16 = self.__W[0]

        # Shift W registers 1 step
        for index in range(15):
            self.__W[index] = self.__W[index + 1]

        # We first decompose W_t-2 and W_t-15
        for index in range(32):
            self.__BITS[index] = (self.__W[13] >> (31 - index)) & 1
            self.__BITS[32 + index] = (self.__W[0] >> (31 - index)) & 1
        
        # We compute the bitwise decomposition of sigma1, sigma0
        for index in range(32):
            right_shift = self.__BITS[32 + index - 3] if index - 3 >= 0 else 0
            right_shift2 = self.__BITS[index - 10] if index - 10 >= 0 else 0

            Sigma0 = self.__BITS[32 + (index - 7) % 32] + self.__BITS[32 + (index - 18) % 32] + right_shift
            Sigma1 = self.__BITS[(index - 17) % 32] + self.__BITS[(index - 19) % 32] + right_shift2

            self.__BITS[64 + index] = Sigma1 % 2
            self.__BITS[128 + index] = Sigma1 // 2

            self.__BITS[96 + index] = Sigma0 % 2
            self.__BITS[160 + index] = Sigma0 // 2

        # The bitwise output registers store the 32-bit equivalent
        power = pow(2, 31)

        self.__BITWISE_OUTPUT[0] = 0
        self.__BITWISE_OUTPUT[1] = 0
        for index in range(32):
            self.__BITWISE_OUTPUT[0] += power * self.__BITS[64 + index]
            self.__BITWISE_OUTPUT[1] += power * self.__BITS[96 + index]
            power //= 2

        # Construct the new message schedule
        self.__W[15] = sum(self.__BITWISE_OUTPUT) + self.__W[8] + W16

        self.__CARRY[0] = 0
        self.__CARRY[1] = 0
        self.__CARRY[2] = 0

        for index in range(3):
            if self.__W[15] < constants.REGISTER_LIMIT:
                break

            self.__W[15] -= constants.REGISTER_LIMIT
            self.__CARRY[index] = 1

        for index in range(32):
            self.__BITS[192 + index] = (self.__W[15] >> (31 - index)) & 1

    def __build_hash_update(self):
        """Updates the current hash blocks
        """
        self.__NUM_ROWS += 1

        self.__HASH[0] += self.__A
        self.__HASH[1] += self.__B
        self.__HASH[2] += self.__C
        self.__HASH[3] += self.__D
        self.__HASH[4] += self.__E
        self.__HASH[5] += self.__F
        self.__HASH[6] += self.__G
        self.__HASH[7] += self.__H

        for index in range(8):
            self.__CARRY[index] = self.__HASH[index] // constants.REGISTER_LIMIT
            self.__HASH[index] = self.__HASH[index] % constants.REGISTER_LIMIT
        
        self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H = self.__HASH

    def __build_size_attestation(self, is_initial = False):
        self.__NUM_ROWS += 1

        registers_per_set = 24
        for set in range(8):
            for i in range(8):
                if is_initial and set == 0:
                    self.__BITS[32 + i] = self.__HASH[i]
                elif set == 0:
                    self.__BITS[32 + i] = self.__BITS[40 + 7 * registers_per_set + i]
                elif set != 0:
                    self.__BITS[32  + set * registers_per_set + i] = self.__BITS[40 + (set - 1) * registers_per_set + i]
                self.__BITS[40 + set * registers_per_set + i] = self.__BITS[32 + set * registers_per_set + i] // 2
                self.__BITS[48 + set * registers_per_set + i] = self.__BITS[32 + set * registers_per_set + i] % 2