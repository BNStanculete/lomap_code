from prover.trace_builders import TraceBuilder, Trace, next_power_of_two
from prover.trace_builders.utils import get_modular_inverse, FIELD_MODULUS
from . import constants, utils
from copy import deepcopy

class Sha256TraceBuilder(TraceBuilder):
    def __init__(self, trace_file: str):
        self.__trace_file = trace_file
        self.__hasPadding = True
        self.__reconstructed = b''

    def debug(self):
        return self.__reconstructed

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def from_message(self, message):
        """Initialize the builder using a message
        """
        self.__message_blocks = utils.from_bytes_to_32bit_blocks(
            utils.as_padded_bytes(message))
        self.__num_blocks = len(self.__message_blocks) // 16
        self.__reset_registers()

    def set_message_blocks(self, message_block: list[int], hash: list[int] = [0] * 8):
        """Initialize the builder using a 512-bit message block.

        Note that this function is intended to be used only when the SHA-256 trace builder is used to construct
        composite (larger) AIR matrices.

        Throws:
            ValueError: More than 1 block provided.
        """
        if len(message_block) != 16:
            raise ValueError("Please use this function only as part of larger traces.")

        for block in message_block:
            self.__reconstructed += block.to_bytes(4)

        self.__message_blocks = message_block
        self.__num_blocks = len(self.__message_blocks) // 16
        self.__reset_registers()

        # Optionally set the previous hash (if any)
        for i in range(8):
            self.__HASH[i] = hash[i]

    def build_trace(self, in_memory) -> Trace:
        trace = Trace()
        blocks_to_process = True

        # Set the initial row
        self.__CONTROL_CODE = constants.CONTROL_CODES["AlignmentStep"]
        self.__set_input_row(True)
        self.__build_row(trace, in_memory)
        self.__update_row_counters()

        # Process the SHA-256 blocks
        while blocks_to_process:
            for round in range(16):
                self.__CONTROL_CODE = constants.CONTROL_CODES["FirstHalfRound"]
                self.__build_first_half_round(round)
                self.__build_row(trace, in_memory)
                self.__update_row_counters()

                self.__CONTROL_CODE = constants.CONTROL_CODES["SecondHalfRound"]
                self.__build_second_half_round()
                self.__build_row(trace, in_memory)
                self.__update_row_counters()

            for round in range(16, 64):
                self.__CONTROL_CODE = constants.CONTROL_CODES["ScheduleUpdate"]
                self.__build_message_schedule()
                self.__build_row(trace, in_memory)
                self.__update_row_counters()

                self.__CONTROL_CODE = constants.CONTROL_CODES["FirstHalfRound"]
                self.__build_first_half_round(round)
                self.__build_row(trace, in_memory)
                self.__update_row_counters()

                self.__CONTROL_CODE = constants.CONTROL_CODES["SecondHalfRound"]
                self.__build_second_half_round()
                self.__build_row(trace, in_memory)
                self.__update_row_counters()

            blocks_to_process = (len(self.__message_blocks) != 0)
            if blocks_to_process:
                self.__set_input_row()

            self.__CONTROL_CODE = constants.CONTROL_CODES["AlignmentStep"]
            self.__build_hash_update()
            self.__build_row(trace, in_memory)
            self.__update_row_counters()

        # Pad to the nearest power of two
        if self.__hasPadding:
            completed_rows = 177 * self.__num_blocks + 1
            self.__PADDING_BIT = 1

            for _ in range(completed_rows, next_power_of_two(completed_rows)):
                self.__build_row(trace, in_memory)
                self.__update_row_counters()
                
        return trace

    def __update_row_counters(self):
        """Increments the row counter and updates the registers that depend on it.
        """
        self.__NUM_ROWS += 1
        self.__QUOTIENT = self.__NUM_ROWS // 177
        self.__REMAINDER = self.__NUM_ROWS % 177
        self.__set_inverse()

    def __set_inverse(self):
        """Computes the modular inverse of 176 - REMAINDER, and stores it in 128-bit limbs.
        """
        if self.__REMAINDER != 176:
            inverse = get_modular_inverse(176 - self.__REMAINDER)
        else:
            inverse = 0

        self.__INVERSE[0] = ((inverse >> 128) & (pow(2, 128) - 1))
        self.__INVERSE[1] = (inverse & (pow(2, 128) - 1))

        if self.__REMAINDER != 176:
            assert (((self.__INVERSE[0] << 128) | self.__INVERSE[1]) * (176 - self.__REMAINDER)) % FIELD_MODULUS == 1, f"Wrong inverse computation for {176 - self.__REMAINDER}"
        else:
            assert self.__INVERSE == [0, 0], f"Inverse not nullified when REMAINDER = 176"

    def __reset_registers(self):
        """Resets the trace registers to their base values.
        """
        self.__NUM_ROWS = 0
        self.__QUOTIENT = 0
        self.__REMAINDER = 0
        self.__INVERSE = [0, 0]
        self.__PADDING_BIT = 0
        self.__CONTROL_CODE = [0, 0]
        self.__W_SELECTOR = [0 for _ in range(17)]
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
        self.__W_SELECTOR[0] = 1
        self.__set_inverse()

    def __build_registers(self) -> list[int]:
        """Converts the registers into a trace row.
        """
        return [
            self.__NUM_ROWS,
            self.__QUOTIENT,
            self.__REMAINDER,
            *self.__INVERSE,
            self.__PADDING_BIT,
            *self.__CONTROL_CODE,
            *self.__W_SELECTOR,
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
            self.__NUM_ROWS = 0
            self.__CARRY = [1 for _ in range(8)]

            for i in range(8):
                if self.__HASH[i] != 0:
                    break
            else:
                # Only put the NIST constants for the first block. Otherwise, keep previous hash
                self.__HASH = deepcopy(constants.INITIAL_HASHES)
            self.__A, self.__B, self.__C, self.__D, self.__E, self.__F, self.__G, self.__H = deepcopy(self.__HASH)

        # Copy the first 16 blocks in the W registers and shift the blocks to the left.
        self.__W = self.__message_blocks[:16]
        self.__message_blocks = self.__message_blocks[16:]

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

    def __build_first_half_round(self, round: int):
        """Builds T1 and updates E,F,G,H
        
        Arguments:
            round (int) : The round index. Used in selecting the appropriate constant.
        """

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

        if self.__W_SELECTOR[-1] != 1:
            for i in range(16, 0, -1):
                self.__W_SELECTOR[i] = self.__W_SELECTOR[i-1]

    def __build_second_half_round(self):
        """Builds T2 and updates A,B,C,D
        """        
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

        for i in range(224):
            self.__BITS[i] = 0
        for i in range(16):
            self.__W[i] = 0
            self.__W_SELECTOR[i] = 0

        self.__W_SELECTOR[0] = 1
        self.__W_SELECTOR[16] = 0

        self.__BITWISE_OUTPUT[0] = 0
        self.__BITWISE_OUTPUT[1] = 0
        self.__T1 = 0
        self.__T2 = 0