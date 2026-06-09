from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two
from . import constants
from copy import deepcopy

class RSA2048TraceBuilder(TraceBuilder):
    def __init__(self, trace_file: str):
        super().__init__()
        self.__reset_registers()
        self.__hasPadding = True
        self.__trace_file = trace_file    

    def from_signed_message(self, representative: int, public_key: tuple[int, int], signature: int):
        """Initialize the trace builder using the public information of a signed message.
        """
        self.__reset_registers()

        for i in range(32):
            self.__N[i] = (public_key[1] >> (2048 - 64 * (i + 1))) & 0xFFFFFFFFFFFFFFFF
            self.__SIGNATURE[i] = (signature >> (2048 - 64 * (i + 1))) & 0xFFFFFFFFFFFFFFFF

        for i in range(4):
            self.__HASH[i] = (representative >> (256 - 64 * (i + 1))) & 0xFFFFFFFFFFFFFFFF

        self.__E = [
            (public_key[0] >> 192) & 0xFFFFFFFFFFFFFFFF,
            (public_key[0] >> 128) & 0xFFFFFFFFFFFFFFFF,
            (public_key[0] >> 64) & 0xFFFFFFFFFFFFFFFF,
            public_key[0] & 0xFFFFFFFFFFFFFFFF
        ]

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def build_trace(self, in_memory) -> Trace:
        trace = Trace()
        
        # Build the first 64 rows attesting to signature < N
        self.__build_initial_attestation(trace, in_memory)

        # The next 8192 * log2 e rows attest to the SQM
        e_copy = deepcopy(self.__E)

        # We initialize BASE to SIGNATURE and REPRESENTATIVE to 1
        self.__BASE = deepcopy(self.__SIGNATURE)
        self.__REPRESENTATIVE[-1] = 1

        for pos in range(3,-1,-1):
            current = e_copy[pos]

            if e_copy[:pos].count(0) == pos:
                # No more registers afterwards
                # We can simply exhaust this one
                while current > 0:
                    current = self.__build_SQM_step(current, trace, in_memory)
                break
            else:
                # There are still non-zero registers
                # We perform mandatory 64 steps
                for _ in range(64):
                    current = self.__build_SQM_step(current, trace, in_memory)

        # Pad to the nearest power of two
        if self.__hasPadding:
            completed_rows = trace.get_length()
            for _ in range(completed_rows, next_power_of_two(completed_rows)):
                self.__build_row(trace, in_memory)

        return trace

    def __reset_registers(self):
        self.__HASH = [0] * 4
        self.__N = [0] * 32
        self.__E = [0, 0, 0, 0]
        self.__SIGNATURE = [0] * 32
        self.__NEXT_E = [0]
        self.__BIT_E = [0]
        self.__BASE = [0] * 32
        self.__REPRESENTATIVE = [0] * 32
        self.__RESULT = [0] * 34
        self.__CARRY = [0] * 33
        self.__QUOTIENT = [0]
        self.__REMAINING = [0] * 187

    def __build_SQM_step(self, current_e: int, trace: Trace, in_memory: bool) -> int:
        # First row of each step also updates the E registers
        self.__BIT_E[0] = current_e % 2
        self.__NEXT_E[0] = current_e // 2

        # Next 4096 rows attest to BASE * REPRESENTATIVE
        if self.__BIT_E[0] == 0:
            for _ in range(4096):
                self.__build_row(trace, in_memory)
        else:
            for multiplier in range(32):
                if multiplier > 0:
                    # Shift all registers 1 step
                    for i in range(1, 34):
                        self.__RESULT[i - 1] = self.__RESULT[i]
                    self.__RESULT[33] = 0

                # -- Multiply the next register
                for i in range(0, 32):
                    aux = self.__RESULT[33 - i] + self.__REPRESENTATIVE[31 - i] * self.__BASE[multiplier]
                    
                    if i > 0:
                        aux += self.__CARRY[33 - i]

                    self.__RESULT[33 - i] = aux % constants.REGISTER_LIMIT
                    self.__CARRY[32 - i] = aux // constants.REGISTER_LIMIT
                
                self.__RESULT[1] += self.__CARRY[1]

                self.__CARRY[0] = self.__RESULT[1] // constants.REGISTER_LIMIT
                self.__RESULT[1] = self.__RESULT[1] % constants.REGISTER_LIMIT

                self.__RESULT[0] += self.__CARRY[0]

                # -- Attest to size (32 rows / multiplication step)
                for attestation_row in range(32):
                    if attestation_row == 0:
                        for i in range(34):
                            self.__REMAINING[i] = self.__RESULT[i] // 2
                        for i in range(33):
                            self.__REMAINING[34 + i] = self.__CARRY[i] // 2
                    else:
                        for i in range(67):
                            self.__REMAINING[i] = self.__REMAINING[67 + i] // 2
                    for i in range(67):
                        self.__REMAINING[67 + i] = self.__REMAINING[i] // 2
                    self.__build_row(trace, in_memory)

                # -- Reduce everything modulo N
                for offset in range(3):
                    if offset == 0:
                        # Estimate the quotient
                        big_result = 0
                        big_n = 0
                        for i in range(32):
                            big_result += self.__RESULT[i + offset]
                            big_n += self.__N[i]

                            if i < 31:
                                big_result *= constants.REGISTER_LIMIT
                                big_n *= constants.REGISTER_LIMIT

                        self.__QUOTIENT[0] = big_result // big_n

                        for i in range(31, -1, -1):
                            self.__RESULT[i] -= self.__QUOTIENT[0] * self.__N[i]

                            if i > 0 and self.__RESULT[i] < 0:
                                carry = (-self.__RESULT[i] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT
                                
                                self.__RESULT[i - 1] -= carry
                                self.__RESULT[i] += carry * constants.REGISTER_LIMIT
                                self.__CARRY[i - 1] = carry
                    else:
                        # Estimate the quotient
                        big_result = self.__RESULT[offset - 1] * constants.REGISTER_LIMIT
                        big_n = 0
                        for i in range(32):
                            big_result += self.__RESULT[i + offset]
                            big_n += self.__N[i]

                            if i < 31:
                                big_result *= constants.REGISTER_LIMIT
                                big_n *= constants.REGISTER_LIMIT

                        self.__QUOTIENT[0] = big_result // big_n

                        for i in range(31, -1, -1):
                            self.__RESULT[i + offset] -= self.__QUOTIENT[0] * self.__N[i]

                            if i == 0 and self.__RESULT[i + offset] < 0:
                                # Carry must be self.__RESULT[i - 1]

                                self.__CARRY[i + offset - 1] = self.__RESULT[i + offset - 1]
                                self.__RESULT[i + offset] += self.__RESULT[i + offset - 1] * constants.REGISTER_LIMIT
                                self.__RESULT[i + offset - 1] = 0
                            elif self.__RESULT[i + offset] < 0:
                                carry = (-self.__RESULT[i + offset] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT

                                self.__RESULT[i + offset - 1] -= carry
                                self.__RESULT[i + offset] += carry * constants.REGISTER_LIMIT
                                self.__CARRY[i + offset - 1] = carry

                    for i in range(34):
                        assert self.__RESULT[i] >= 0, f"Invalid trace at {offset} and {multiplier} for base: {self.__RESULT[i]}"
                    
                    # We attest that QUOTIENT, CARRY and RESULT are still valid numbers
                    for attestation_row in range(32):
                        if attestation_row == 0:
                            for i in range(32):
                                self.__REMAINING[i] = self.__RESULT[i + offset] // 2
                            for i in range(31):   
                                self.__REMAINING[32 + i] = self.__CARRY[i + offset] // 2
                            self.__REMAINING[63] = self.__QUOTIENT[0] // 2
                        else:
                            for i in range(64):
                                self.__REMAINING[i] = self.__REMAINING[64 + i] // 2
                        for i in range(64):
                            self.__REMAINING[64 + i] = self.__REMAINING[i] // 2
                        self.__build_row(trace, in_memory)
            
            # Copy in REPRESENTATIVE
            self.__REPRESENTATIVE = deepcopy(self.__RESULT[2:])
            self.__RESULT = [0] * 34
            self.__build_row(trace, in_memory)

        # Next 4096 rows attest to BASE * BASE
        for multiplier in range(32):
            if multiplier > 0:
                # Shift all registers 1 step
                for i in range(1, 34):
                    self.__RESULT[i - 1] = self.__RESULT[i]
                self.__RESULT[33] = 0

            # -- Multiply the next register
            for i in range(0, 32):
                aux = self.__RESULT[33 - i] + self.__BASE[31 - i] * self.__BASE[multiplier]
                
                if i > 0:
                    aux += self.__CARRY[33 - i]

                self.__RESULT[33 - i] = aux % constants.REGISTER_LIMIT
                self.__CARRY[32 - i] = aux // constants.REGISTER_LIMIT
            
            self.__RESULT[1] += self.__CARRY[1]

            self.__CARRY[0] = self.__RESULT[1] // constants.REGISTER_LIMIT
            self.__RESULT[1] = self.__RESULT[1] % constants.REGISTER_LIMIT

            self.__RESULT[0] += self.__CARRY[0]

            # -- Attest to size (32 rows / multiplication step)
            for attestation_row in range(32):
                if attestation_row == 0:
                    for i in range(34):
                        self.__REMAINING[i] = self.__RESULT[i] // 2
                    for i in range(33):
                        self.__REMAINING[34 + i] = self.__CARRY[i] // 2
                else:
                    for i in range(67):
                        self.__REMAINING[i] = self.__REMAINING[67 + i] // 2
                for i in range(67):
                    self.__REMAINING[67 + i] = self.__REMAINING[i] // 2
                self.__build_row(trace, in_memory)

            # -- Reduce everything modulo N
            for offset in range(3):
                if offset == 0:
                    # Estimate the quotient
                    big_result = 0
                    big_n = 0
                    for i in range(32):
                        big_result += self.__RESULT[i + offset]
                        big_n += self.__N[i]

                        if i < 31:
                            big_result *= constants.REGISTER_LIMIT
                            big_n *= constants.REGISTER_LIMIT

                    self.__QUOTIENT[0] = big_result // big_n

                    for i in range(31, -1, -1):
                        self.__RESULT[i] -= self.__QUOTIENT[0] * self.__N[i]

                        if i > 0 and self.__RESULT[i] < 0:
                            carry = (-self.__RESULT[i] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT
                            
                            self.__RESULT[i - 1] -= carry
                            self.__RESULT[i] += carry * constants.REGISTER_LIMIT
                            self.__CARRY[i - 1] = carry
                else:
                    # Estimate the quotient
                    big_result = self.__RESULT[offset - 1] * constants.REGISTER_LIMIT
                    big_n = 0
                    for i in range(32):
                        big_result += self.__RESULT[i + offset]
                        big_n += self.__N[i]

                        if i < 31:
                            big_result *= constants.REGISTER_LIMIT
                            big_n *= constants.REGISTER_LIMIT

                    self.__QUOTIENT[0] = big_result // big_n

                    for i in range(31, -1, -1):
                        self.__RESULT[i + offset] -= self.__QUOTIENT[0] * self.__N[i]

                        if i == 0 and self.__RESULT[i + offset] < 0:
                            # Carry must be self.__RESULT[i - 1]

                            self.__CARRY[i + offset - 1] = self.__RESULT[i + offset - 1]
                            self.__RESULT[i + offset] += self.__RESULT[i + offset - 1] * constants.REGISTER_LIMIT
                            self.__RESULT[i + offset - 1] = 0
                        elif self.__RESULT[i + offset] < 0:
                            carry = (-self.__RESULT[i + offset] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT

                            self.__RESULT[i + offset - 1] -= carry
                            self.__RESULT[i + offset] += carry * constants.REGISTER_LIMIT
                            self.__CARRY[i + offset - 1] = carry
                
                for i in range(34):
                    assert self.__RESULT[i] >= 0, f"Invalid trace at {offset} and {multiplier} for base: {self.__RESULT[i]}"
                    
                # We attest that QUOTIENT, CARRY and RESULT are still valid numbers
                for attestation_row in range(32):
                    if attestation_row == 0:
                        for i in range(32):
                            self.__REMAINING[i] = self.__RESULT[i + offset] // 2
                        for i in range(31):   
                            self.__REMAINING[32 + i] = self.__CARRY[i + offset] // 2
                        self.__REMAINING[63] = self.__QUOTIENT[0] // 2
                    else:
                        for i in range(64):
                            self.__REMAINING[i] = self.__REMAINING[64 + i] // 2
                    for i in range(64):
                        self.__REMAINING[64 + i] = self.__REMAINING[i] // 2
                    self.__build_row(trace, in_memory)

        # Copy in REPRESENTATIVE
        self.__BASE = deepcopy(self.__RESULT[2:])
        self.__RESULT = [0] * 34
        self.__build_row(trace, in_memory)

        return self.__NEXT_E[0]

    def __build_initial_attestation(self, trace: Trace, in_memory: bool):
        # -- Perform register remapping --
        REMAINING = RegisterView(
            (self.__NEXT_E, 0, 1),
            (self.__BIT_E, 0, 1),
            (self.__BASE, 0, 32),
            (self.__REPRESENTATIVE, 0, 30))

        NEXT = RegisterView(
            (self.__REPRESENTATIVE, 30, 2),
            (self.__RESULT, 0, 34),
            (self.__CARRY, 0, 28))

        BIT = RegisterView(
            (self.__CARRY, 28, 5),
            (self.__REMAINING, 0, 59))

        BIT_LT = RegisterView(
            (self.__REMAINING, 59, 32))

        BIT_GT = RegisterView(
            (self.__REMAINING, 91, 32))
        
        REGISTER_LT = RegisterView(
            (self.__REMAINING, 123, 32))

        SET_LT = RegisterView(
            (self.__REMAINING, 155, 32))

        for row in range(64):
            # -- Initialize the Remaining registers to the corresponding values --
            if row == 0:
                for i in range(32):
                    REMAINING[i] = self.__N[i]
                    REMAINING[i + 32] = self.__SIGNATURE[i]
            else:
                for i in range(64):
                    REMAINING[i] = deepcopy(NEXT[i])

            # -- Execute row
            for i in range(64):
                NEXT[i] = REMAINING[i] // 2
                BIT[i] = REMAINING[i] % 2
            
            for i in range(32):
                BIT_LT[i] = (1 - BIT[32 + i]) * BIT[i]
                BIT_GT[i] = BIT[32 + i] * (1 - BIT[i])

                if row == 0:
                    REGISTER_LT[i] = (1 - BIT_LT[i] - BIT_GT[i]) + 2 * BIT_GT[i]
                else:
                    REGISTER_LT[i] = (1 - BIT_LT[i] - BIT_GT[i]) * REGISTER_LT[i] + 2 * BIT_GT[i]

            SET_LT[0] = REGISTER_LT[0]
            for i in range(1, 32):
                SET_LT[i] = SET_LT[i-1] * (2 - SET_LT[i-1]) * REGISTER_LT[i] + SET_LT[i - 1] * (SET_LT[i - 1] - 1)

            # Build row
            self.__build_row(trace, in_memory)

    def __build_registers(self) -> list[int]:
        """Builds the registers into a single trace row.

        Returns:
            list[int]: The trace row encoded by the registers.
        """

        return [
            *self.__HASH,
            *self.__N,
            *self.__E,
            *self.__SIGNATURE,
            *self.__NEXT_E,
            *self.__BIT_E,
            *self.__BASE,
            *self.__REPRESENTATIVE,
            *self.__RESULT,
            *self.__CARRY,
            *self.__QUOTIENT,
            *self.__REMAINING
        ]
    
    def __build_row(self, trace: Trace, in_memory: bool):
        """Saves the next row of the trace.

        If the in_memory flag is False, the row is immediatelly written to file.

        Arguments:
            trace (RSA2048Trace): The trace that is currently being built
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
