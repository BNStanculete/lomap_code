from __future__ import annotations
from abc import ABC, abstractmethod

class Trace(ABC):
    # Dimension Queries
    # ===================================================================
    @abstractmethod
    def get_length(self) -> int:
        """Returns the number of rows in the trace.
        """
        pass
    
    @abstractmethod
    def get_width(self) -> int:
        """Returns the trace width (number of registers)
        """
        pass

    def as_list(self) -> list:
        """Returns the trace as a matrix of values.
        """
        pass

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
            self._extend_horizontally(trace)
        else:
            if self.get_width() != trace.get_width():
                raise ValueError(f"Extension width was {trace.get_width()}, expected {self.get_width()}.")
            self._extend_vertically()

    @abstractmethod
    def _extend_vertically(self, trace: Trace) -> None:
        """Extends the existing trace vertically with another trace.

        Arguments:
            trace (Trace): The trace extension.
        """
        pass

    @abstractmethod
    def _extend_horizontally(self, trace: Trace) -> None:
        """Extends the trace horizontally with another Trace.

        Arguments:
            trace (Trace): The trace extension.
        """
        pass

    # Persistance
    # ================================================================================================
    def write_to_file(self, file_path: str) -> None:
        """Writes the trace contents to a specified file.

        Arguments:
            file_path (str) : The path where to write the file
        """
        for row_id in range(self.get_length()):
            self._write_row_to_file(row_id, file_path)

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
        
        self._write_row_to_file(row_id, file_path)

    @abstractmethod
    def _write_row_to_file(self, row_id: int, file_path: str) -> None:
        """Writes a given row in the trace to a specified file.

        Arguments:
            row_id (int) : The row index.
            file_path (str) : The path where to write the file        
        """
        pass