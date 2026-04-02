# from trace_builders.sha256 import Sha256TraceBuilder
from trace_builders.rsa2048 import RSA2048TraceBuilder
from subprocess import run
from json import dump

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils

import time
import tracemalloc

def get_pwd() -> str:
    """Returns the path to the working directory"""

    return run(["pwd"], capture_output=True).stdout[:-1].decode()

if __name__ == '__main__':
    file_path = f"{get_pwd()}/data/trace_data/rsa2048.trace.txt"

    # Generate RSA-2048 private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract public key
    public_key = private_key.public_key()

    # Message to sign
    message = b"Hello, this is a signed message"

    # Sign the message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_int = int.from_bytes(signature, "big")

    # Compute representative
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash = digest.finalize()

    hash_int = int.from_bytes(hash)

    der_encoded = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    ) + hash
    PS_len = 256 - len(der_encoded) - 3
    if PS_len < 8:
        raise ValueError("Key too small for PKCS#1 v1.5 padding")
    representative = b"\x00\x01" + b"\xFF" * PS_len + b"\x00" + der_encoded
    representative_int = int.from_bytes(representative, "big")

    # builder = Sha256TraceBuilder(message, file_path)
    builder = RSA2048TraceBuilder(hash_int, (public_key.public_numbers().e, public_key.public_numbers().n), signature_int, file_path)

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

    with open(f"{get_pwd()}/data/trace_data/rsa2048.benchmarks", "w") as file:
        dump(jsonBenchmarks, file)
