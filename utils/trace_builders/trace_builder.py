from abc import ABC, abstractmethod
from trace import Trace

class TraceBuilder(ABC):
    @abstractmethod
    def build_trace(self, in_memory: bool) -> Trace:
        """Builds an AIR trace for a computation.

        Arguments:
            in_memory (bool) : Flag. When set to True, rows are kept in memory.
                Otherwise, rows are written to file as they are completed.
        
        Returns:
            Trace : the AIR trace.
        """
        pass