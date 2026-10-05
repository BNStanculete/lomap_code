from prover.trace_builders import TraceBuilder, Trace, next_power_of_two
from prover.trace_builders.utils import FIELD_MODULUS
from . import constants

class PoseidonTraceBuilder(TraceBuilder):
    def build_trace(self, in_memory):
        trace = Trace()

        # Build the initial row
        # self.__build_row(trace, in_memory)

        while self.__blocks != []:
            index = 0
            self.__INPUT_STATE[0] += self.__blocks[0]
            self.__INPUT_STATE[1] += self.__blocks[1]
            self.__normalize_states()
            self.__blocks = self.__blocks[2:]

            for _ in range(constants.FULL_ROUNDS // 2):
                self.__perform_round(index, True)
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1
                self.__INPUT_STATE[0] = self.__OUTPUT_STATE[0]
                self.__INPUT_STATE[1] = self.__OUTPUT_STATE[1]
                self.__INPUT_STATE[2] = self.__OUTPUT_STATE[2]

                index += 1

            for _ in range(constants.PARTIAL_ROUNDS):
                self.__perform_round(index, False)
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1
                self.__INPUT_STATE[0] = self.__OUTPUT_STATE[0]
                self.__INPUT_STATE[1] = self.__OUTPUT_STATE[1]
                self.__INPUT_STATE[2] = self.__OUTPUT_STATE[2]

                index += 1

            for _ in range(constants.FULL_ROUNDS // 2):
                self.__perform_round(index, True)
                self.__build_row(trace, in_memory)
                self.__NUM_ROWS += 1
                self.__INPUT_STATE[0] = self.__OUTPUT_STATE[0]
                self.__INPUT_STATE[1] = self.__OUTPUT_STATE[1]
                self.__INPUT_STATE[2] = self.__OUTPUT_STATE[2]

                index += 1

        # Final padding
        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)

        return trace

    def get_digest(self):
        return self.__OUTPUT_STATE[0]

    def set_blocks(self, blocks: list[int]):
        self.__reset_registers()
        self.__blocks = blocks

        # Pad the blocks to fit the rate.
        self.__blocks.append(1)
        if len(self.__blocks) % 2 == 1:
            self.__blocks.append(0)

    def absorb_block(self, block: list[int, int]):
        self.__NUM_ROWS = 1
        self.__FULL_ROUND = 0
        self.__ROUND_CONSTANTS = [0] * 3
        self.__INPUT_STATE = self.__OUTPUT_STATE
        self.__OUTPUT_STATE = [0] * 3
        self.__blocks = block

    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def __perform_round(self, round_index: int, full_round: bool):
        round_constants = constants.ROUND_CONSTANTS[round_index]
        result = [
            self.__INPUT_STATE[0] + round_constants[0],
            self.__INPUT_STATE[1] + round_constants[1],
            self.__INPUT_STATE[2] + round_constants[2]
        ]

        self.__ROUND_CONSTANTS[0] = round_constants[0]
        self.__ROUND_CONSTANTS[1] = round_constants[1]
        self.__ROUND_CONSTANTS[2] = round_constants[2]

        if full_round:
            self.__FULL_ROUND = 1

            for i in range(3):
                result[i] = pow(result[i], 3, FIELD_MODULUS)
        else:
            self.__FULL_ROUND = 0
            result[2] **= 3

        self.__OUTPUT_STATE[0] = 3 * result[0] + result[1] + result[2]
        self.__OUTPUT_STATE[1] = result[0] - result[1] + result[2]
        self.__OUTPUT_STATE[2] = result[0] + result[1] - 2 * result[2]
        self.__normalize_states()

    def __normalize_states(self):
        for i in range(3):
            self.__INPUT_STATE[i] %= FIELD_MODULUS
            self.__OUTPUT_STATE[i] %= FIELD_MODULUS

    def __pad_rows(self, trace, in_memory):
        for _ in range(self.__NUM_ROWS, next_power_of_two(self.__NUM_ROWS)):
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

    def __init__(self, trace_file: str):
        super().__init__()
        self.__reset_registers()
        self.__hasPadding = True
        self.__trace_file = trace_file    

    def __reset_registers(self):
        self.__NUM_ROWS = 1
        self.__FULL_ROUND = 0
        self.__INPUT_STATE = [0] * 3
        self.__ROUND_CONSTANTS = [0] * 3
        self.__OUTPUT_STATE = [0] * 3

    def __build_registers(self) -> list[int]:
        """Builds the registers into a single trace row.

        Returns:
            list[int]: The trace row encoded by the registers.
        """

        return [
            self.__NUM_ROWS,
            self.__FULL_ROUND,
            *self.__INPUT_STATE,
            *self.__ROUND_CONSTANTS,
            *self.__OUTPUT_STATE
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