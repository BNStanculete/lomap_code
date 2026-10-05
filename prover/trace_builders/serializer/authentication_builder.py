from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two, get_modular_inverse
from prover.trace_builders.serializer import CrlTraceBuilder, CertificateTraceBuilder
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from prover.trace_builders.sha256.constants import ROUND_CONSTANTS
from prover.trace_builders.utils import FIELD_MODULUS

from ast import literal_eval

from . import constants
from . import utils

from functools import partial
from collections.abc import Callable

class AuthenticationTraceBuilder(TraceBuilder):
    def togglePadding(self):
        """Toggles whether to pad the trace to the nearest power of two.
        """
        self.__hasPadding = not self.__hasPadding

    def setPadding(self, padding):
        self.__hasPadding = padding

    def set_input(self, input_data: dict):
        self.__input_data = input_data
        self.__reset_registers()

    def build_trace(self, in_memory):
        trace = Trace()

        current = "ProverCertificate"
        while current != "":
            self.__certbuilder.set_input(self.__input_data[current]["Certificate"])
            cert_trace = self.__certbuilder.build_trace(True)

            for row in cert_trace.as_list():
                for col in range(1, len(row)):
                    self.__REGISTERS[col - 1] = row[col]
                self.__NUM_ROWS += 1
                self.__build_row(trace, in_memory)

            next = self.__input_data[current]["NextInChain"]
            if next != "":
                self.__crlbuilder.set_input(self.__input_data[next]["CRL"])
                crl_trace = self.__crlbuilder.build_trace(True)

                for row in crl_trace.as_list():
                    for col in range(1, len(row)):
                        self.__REGISTERS[col - 1] = row[col]
                    self.__NUM_ROWS += 1
                    self.__build_row(trace, in_memory)
            current = next

        if self.__hasPadding:
            self.__pad_rows(trace, in_memory)
        return trace

    def __pad_rows(self, trace, in_memory):
        # BUG: SET OPBITS

        self.__NUM_ROWS += 1
        target_rows = next_power_of_two(self.__NUM_ROWS)

        for _ in range(self.__NUM_ROWS, target_rows):
            self.__build_row(trace, in_memory)
            self.__NUM_ROWS += 1

    def __init__(self, trace_file: str):
        self.__reset_registers()
        self.__crlbuilder = CrlTraceBuilder(trace_file)
        self.__certbuilder = CertificateTraceBuilder(trace_file)
        self.__trace_file = trace_file

        self.__crlbuilder.togglePadding()
        self.__certbuilder.togglePadding()
        self.__hasPadding = True

    def __reset_registers(self):
        self.__NUM_ROWS = -1
        self.__REGISTERS = [0] * 402

    def __build_registers(self):
        return [
            self.__NUM_ROWS,
            *self.__REGISTERS
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