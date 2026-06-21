from prover.trace_builders import TraceBuilder, Trace, next_power_of_two
from prover.trace_builders.utils import FIELD_MODULUS
from . import constants

class RSA2048TraceBuilder(TraceBuilder):
    def build_trace(self, in_memory):
        trace = Trace()

        # Build the initial row
        self.__build_row(trace, in_memory)

        for idx in range(3, -1, -1):
            # We exhaust self.__E in LSB order.

            if self.__can_terminate_early(idx):
                # We simply exhaust the current register
                while self.__E[idx] > 0:
                    self.__build_SQM_step(idx, trace, in_memory)
                break
            else:
                for _ in range(64):
                    self.__build_SQM_step(idx, trace, in_memory)

        assert self.__HASH == self.__REPRESENTATIVE[28:], f"{self.__HASH} vs {self.__REPRESENTATIVE}"

        # Final padding
        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)

        return trace

    def set_input(self, representative: int, public_key: list[int, int], signature: int):
        self.__reset_registers()
        self.__NUM_ROWS = 1
        self.__REPRESENTATIVE[-1] = 1

        for idx in range(4):
            self.__HASH[idx] = (representative >> (192 - 64 * idx)) & constants.REGISTER_MASK
            self.__E[idx] = (public_key[0] >> (192 - 64 * idx)) & constants.REGISTER_MASK

        for idx in range(32):
            self.__N[idx] = (public_key[1] >> (1984 - 64 * idx)) & constants.REGISTER_MASK
            self.__SIGNATURE[idx] = (signature >> (1984 - 64 * idx)) & constants.REGISTER_MASK

        # We also keep the bigint values to avoid recombinations later.
        self.__modulus = public_key[1]
        self.__signature = signature
        self.__representative = 1

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def __build_SQM_step(self, e_idx: int, trace, in_memory):
        # 1) Extract the current bit of E
        self.__NEXT_E = self.__E[e_idx] // 2
        self.__BIT_E = self.__E[e_idx] % 2

        # 2) If the current bit is 1, multiply SIGNATURE with REPRESENTATIVE, otherwise just copy the previous row
        if self.__BIT_E == 1:
            for signature_index in range(32):
                for representative_index in range(32):
                    self.__RESULT[1 + signature_index + representative_index] += self.__SIGNATURE[signature_index] * self.__REPRESENTATIVE[representative_index]
                    assert self.__RESULT[1 + signature_index + representative_index] < FIELD_MODULUS, f"Overflow at indexes {signature_index} and {representative_index}"

            # Now we calculate the carries and update the results
            for idx in range(63, -1, -1):
                self.__RESULT[idx] += self.__CARRY[idx] if idx != 63 else 0
                
                if idx > 0:
                    self.__CARRY[idx - 1] = self.__RESULT[idx] // constants.REGISTER_LIMIT
    
                self.__RESULT[idx] %= constants.REGISTER_LIMIT
            self.__build_step_rows(trace, in_memory)

            # Now we reduce everything modulo N. For that, we compute the quotient using bigint
            self.__representative *= self.__signature
            quotient = self.__representative // self.__modulus
            self.__representative %= self.__modulus

            # Now we simply set the quotient in register
            self.__CARRY = [0] * 63
            
            for idx in range(32):
                self.__QUOTIENT[idx] = (quotient >> (1984 - 64 * idx)) & constants.REGISTER_MASK

            # Note that this might produce negatives. For that, we use carries
            for modulus_index in range(32):
                for quotient_index in range(32):
                    self.__RESULT[1 + modulus_index + quotient_index] -= self.__N[modulus_index] * self.__QUOTIENT[quotient_index]

            for idx in range(63, -1, -1):
                if idx != 63:
                    self.__RESULT[idx] -= self.__CARRY[idx]

                if idx > 0 and self.__RESULT[idx] < 0:
                    borrow = (-self.__RESULT[idx] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT
                    self.__RESULT[idx] += borrow * constants.REGISTER_LIMIT
                    self.__CARRY[idx - 1] = borrow

                    assert self.__RESULT[idx] >= 0 and self.__RESULT[idx] < constants.REGISTER_LIMIT, f"Wrong reduction at index {idx}"

            for idx in range(32):
                assert self.__RESULT[idx] == 0, f"Wrong modular reduction at index {idx}"                    

            # We also copy the upper 32-limbs into representative
            for idx in range(32):
                self.__REPRESENTATIVE[idx] = self.__RESULT[32 + idx]
            self.__E[e_idx] = self.__NEXT_E

            self.__build_step_rows(trace, in_memory)
        else:
            self.__E[e_idx] = self.__NEXT_E
            for _ in range(256):
                self.__NUM_ROWS += 1
                self.__build_row(trace, in_memory)

        # Now we square the SIGNATURE
        self.__CARRY = [0] * 63
        self.__RESULT = [0] * 64

        # In practice, this should fit in 128-bit field.
        for signature_index in range(32):
            for signature_index2 in range(32):
                self.__RESULT[1 + signature_index + signature_index2] += self.__SIGNATURE[signature_index] * self.__SIGNATURE[signature_index2]
                assert self.__RESULT[1 + signature_index + signature_index2] < FIELD_MODULUS, f"Overflow at indexes {signature_index} and {signature_index2}"

        # Now we calculate the carries and update the results
        for idx in range(63, -1, -1):
            self.__RESULT[idx] += self.__CARRY[idx] if idx != 63 else 0
            
            if idx > 0:
                self.__CARRY[idx - 1] = self.__RESULT[idx] // constants.REGISTER_LIMIT

            self.__RESULT[idx] %= constants.REGISTER_LIMIT
        self.__build_step_rows(trace, in_memory)

        # Now we reduce everything modulo N. For that, we compute the quotient using bigint
        self.__signature *= self.__signature
        quotient = self.__signature // self.__modulus
        self.__signature %= self.__modulus

        # Now we simply set the quotient in register
        self.__CARRY = [0] * 63
        
        for idx in range(32):
            self.__QUOTIENT[idx] = (quotient >> (1984 - 64 * idx)) & constants.REGISTER_MASK

        # Note that this might produce negatives. For that, we use carries
        for modulus_index in range(32):
            for quotient_index in range(32):
                self.__RESULT[1 + modulus_index + quotient_index] -= self.__N[modulus_index] * self.__QUOTIENT[quotient_index]

        for idx in range(63, -1, -1):
            if idx != 63:
                self.__RESULT[idx] -= self.__CARRY[idx]

            if idx > 0 and self.__RESULT[idx] < 0:
                borrow = (-self.__RESULT[idx] + constants.REGISTER_LIMIT - 1) // constants.REGISTER_LIMIT
                self.__RESULT[idx] += borrow * constants.REGISTER_LIMIT
                self.__CARRY[idx - 1] = borrow

                assert self.__RESULT[idx] >= 0 and self.__RESULT[idx] < constants.REGISTER_LIMIT, f"Wrong reduction at index {idx}"

        for idx in range(32):
            assert self.__RESULT[idx] == 0, f"Wrong modular reduction at index {idx}"                    

        # We also copy the upper 32-limbs into SIGNATURE
        for idx in range(32):
            self.__SIGNATURE[idx] = self.__RESULT[32 + idx]
        self.__build_step_rows(trace, in_memory)

        # Reset the result and carry
        self.__RESULT = [0] * 64
        self.__CARRY = [0] * 63


    def __build_step_rows(self, trace, in_memory):
        # Now we set the initial values of the ATTESTORS. their job is to attest that each number is 64-bit
        for idx in range(64):
            self.__ATTESTORS[idx] = self.__RESULT[idx] // 2
            
            if idx < 63:
                self.__ATTESTORS[64 + idx] = self.__CARRY[idx] // 2

        # We build the multiplication row
        self.__NUM_ROWS += 1
        self.__build_row(trace, in_memory)

        # Next 63 rows just update the ATTESTORS. If the registers are indeed 64-bit, the final ATTESTOR must be 0
        for _ in range(63):
            self.__NUM_ROWS += 1
            
            for idx in range(127):
                self.__ATTESTORS[idx] //= 2
            
            self.__build_row(trace, in_memory)


    def __can_terminate_early(self, current_index):
        """Checks whether all the upper registers of E are 0.
        """
        return self.__E[:current_index].count(0) == current_index

    def __pad_rows(self, trace, in_memory):
        target_rows = next_power_of_two(self.__NUM_ROWS)

        for _ in range(self.__NUM_ROWS, target_rows):
            self.__NUM_ROWS += 1
            self.__build_row(trace, in_memory)

    def __init__(self, trace_file: str):
        super().__init__()
        self.__reset_registers()
        self.__hasPadding = True
        self.__trace_file = trace_file    

    def __reset_registers(self):
        self.__NUM_ROWS = 0
        self.__HASH = [0] * 4
        self.__E = [0] * 4
        self.__N = [0] * 32
        self.__SIGNATURE = [0] * 32
        self.__NEXT_E = 0
        self.__BIT_E = 0
        self.__REPRESENTATIVE = [0] * 32
        self.__RESULT = [0] * 64
        self.__CARRY = [0] * 63
        self.__QUOTIENT = [0] * 32
        self.__ATTESTORS = [0] * 127

    def __build_registers(self) -> list[int]:
        """Builds the registers into a single trace row.

        Returns:
            list[int]: The trace row encoded by the registers.
        """

        return [
            self.__NUM_ROWS,
            *self.__HASH,
            *self.__N,
            *self.__E,
            *self.__SIGNATURE,
            self.__NEXT_E,
            self.__BIT_E,
            *self.__REPRESENTATIVE,
            *self.__RESULT,
            *self.__CARRY,
            *self.__QUOTIENT,
            *self.__ATTESTORS
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
