from trace_builders.sha256 import Sha256TraceBuilder
from subprocess import run
from json import dump

import time
import tracemalloc

def get_pwd() -> str:
    """Returns the path to the working directory"""

    return run(["pwd"], capture_output=True).stdout[:-1].decode()

if __name__ == '__main__':
    file_path = f"{get_pwd()}/data/trace_data/sha256.trace.txt"
    message = "abc".encode('utf-8')

    builder = Sha256TraceBuilder(message, file_path)

    start = time.perf_counter_ns()
    tracemalloc.start()

    trace = builder.build_trace(False)

    end = time.perf_counter_ns()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()


    # Write benchmarks
    jsonBenchmarks = {
        "Runtime": (end - start) / 1000000,
        "Memory": peak
    }

    with open(f"{get_pwd()}/data/trace_data/sha256.benchmarks", "w") as file:
        dump(jsonBenchmarks, file)
