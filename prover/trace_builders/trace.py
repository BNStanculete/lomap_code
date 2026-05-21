from __future__ import annotations
from copy import deepcopy

class Trace:
    def __init__(self):
        self.__trace = [] 

    # Dimension Queries
    # ===================================================================
    def get_length(self) -> int:
        """Returns the number of rows in the trace.
        """
        return len(self.__trace)
    
    def get_width(self) -> int:
        """Returns the trace width (number of registers)
        """
        if self.__trace != []:
            return len(self.__trace[0])
        return 0

    def as_list(self) -> list[list[int]]:
        """Returns the trace as a matrix of values.
        """
        return self.__trace

    # Row Accessor
    # ====================================================================
    def get_row(self, idx: int) -> list[int]:
        """Returns the specified row.

        Arguments:
            idx (int): The row index.

        Throws:
            ValueError: Index is out of bounds.
        """
        if idx > self.get_length() or idx < -1 * self.get_length():
            raise ValueError(f"Invalid index row {idx}. Valid bounds are ({-1 * self.get_length(), self.get_length()}).")
        return self.__trace[idx]

    # Padding
    # ====================================================================
    def pad_rows(self, target_rows: int) -> None:
        """Copies the last row until the target is reached.

        Arguments:
            target_rows (int): The target rows to reach through padding
        """
        if target_rows <= len(self.__trace):
            pass

        for _ in range(len(self.__trace) - 1, target_rows):
            self.__trace.append(deepcopy(self.__trace[-1]))

    def pad_columns(self, target_columns: int) -> None:
        """Adds zeroes until the target columns is reached.

        Arguments:
            target_columns (int): The target columns to reach through padding
        """
        if self.__trace == [] or target_columns <= len(self.__trace[0]):
            pass

        columns_to_add = target_columns - len(self.__trace[0])
        for row_idx in range(len(self.__trace)):
            for _ in range(columns_to_add):
                self.__trace[row_idx].append(0)

    # Extension methods
    # ====================================================================
    def extend(self, trace: Trace, horizontal: bool = False) -> None:
        """Extends the existing trace with another trace.

        Arguments:
            trace (Trace): The trace extension.
            horizontal (bool) : When true, the extension happens horizontally, otherwise
                    the extension happens vertically. Defaults to False.
        
        Throws:
            ValueError : there is a mismatch in the number of columns / rows between the two traces.
        """
        if horizontal:
            if self.get_length() != trace.get_length():
                raise ValueError(f"Extension length was {trace.get_length()}, expected {self.get_length()}.")
            self.__extend_horizontally(trace)
        else:
            if self.get_width() != trace.get_width():
                raise ValueError(f"Extension width was {trace.get_width()}, expected {self.get_width()}.")
            self.__extend_vertically()

    def __extend_vertically(self, trace: Trace) -> None:
        """Extends the existing trace vertically with another trace.

        Arguments:
            trace (Trace): The trace extension.
        """
        trace_matrix = trace.as_list()

        for row in trace_matrix:
            self.__trace.append(row)

    def __extend_horizontally(self, trace: Trace) -> None:
        """Extends the trace horizontally with another Trace.

        Arguments:
            trace (Trace): The trace extension.
        """
        trace_matrix = trace.as_list()

        for row_index in range(0, self.__height):
            self.__trace[row_index].extend(trace_matrix[row_index])

    # Persistance
    # ================================================================================================
    def read_from_file(self, file_path: str) -> None:
        """Reads a new trace from a specified file.

        Arguments:
            file_path (str) : The path to the trace fle.
        
        Throws:
            ValueError : The file is not readable or rows have different widths.

        Warning:
            This overwrites the currently stored trace.
        """
        self.__trace = []

        expected_width = 0
        with open(file_path, "r") as file:
            if not file.readable():
                raise ValueError(f"Unreadable file {file_path}.")

            line = file.readline()
            while line != "":
                elements = [int(x) for x in line.split(" ")]

                if expected_width == 0:
                    expected_width = len(elements)
                elif len(elements) != expected_width:
                    self.__trace = []
                    raise ValueError(f"Expected row of length {expected_width} but got {len(elements)}.")

                self.__trace.append(deepcopy(elements))

    def write_to_file(self, file_path: str) -> None:
        """Writes the trace contents to a specified file.

        Arguments:
            file_path (str) : The path where to write the file
        """
        for row_id in range(self.get_length()):
            self.write_row_to_file(row_id, file_path)

    def write_row_to_file(self, row_id: int, file_path: str) -> None:
        """Writes a given row in the trace to a specified file.

        Arguments:
            row_id (int) : The row index.
            file_path (str) : The path where to write the file
        
        Throws:
            ValueError : The provided index is negative, or too large.
        """
        if row_id < 0 or row_id >= self.get_length():
            raise ValueError(f"Invalid row id {row_id}.")
        
        with open(file_path, "a") as file:
            for value in self.__trace[row_id]:
                file.write(str(value))
                file.write(" ")
            file.write("\n")
