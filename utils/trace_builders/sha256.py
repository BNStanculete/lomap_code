from hashlib import sha256
from subprocess import run

import time
import tracemalloc

from json import dump

CYCLE_LENGTH = 177
PADDED_CYCLE_LENGTH = 256
TRACE_WIDTH = 271

NUM_ROWS = 0
W = [0 for _ in range(16)]
A,B,C,D,E,F,G,H,T1,T2 = 0,0,0,0,0,0,0,0,0,0
BITS = [0 for _ in range(224)]
BITWISE_OUTPUT = [0, 0]
CARRY = [0 for _ in range(10)]
HASH = [0 for _ in range(8)]

# REGISTERS = [0 for _ in range(TRACE_WIDTH)]
LIMIT = pow(2, 32)

INITIAL_HASHES = [
    int("0x6a09e667",16),
    int("0xbb67ae85",16),
    int("0x3c6ef372",16),
    int("0xa54ff53a",16),
    int("0x510e527f",16),
    int("0x9b05688c",16),
    int("0x1f83d9ab",16),
    int("0x5be0cd19",16)
]

ROUND_CONSTANTS = [
    int("0x428a2f98",16),
    int("0x71374491",16),
    int("0xb5c0fbcf",16),
    int("0xe9b5dba5",16),
    int("0x3956c25b",16),
    int("0x59f111f1",16),
    int("0x923f82a4",16),
    int("0xab1c5ed5",16),
    int("0xd807aa98",16),
    int("0x12835b01",16),
    int("0x243185be",16),
    int("0x550c7dc3",16),
    int("0x72be5d74",16),
    int("0x80deb1fe",16),
    int("0x9bdc06a7",16),
    int("0xc19bf174",16),
    int("0xe49b69c1",16),
    int("0xefbe4786",16),
    int("0x0fc19dc6",16),
    int("0x240ca1cc",16),
    int("0x2de92c6f",16),
    int("0x4a7484aa",16),
    int("0x5cb0a9dc",16),
    int("0x76f988da",16),
    int("0x983e5152",16),
    int("0xa831c66d",16),
    int("0xb00327c8",16),
    int("0xbf597fc7",16),
    int("0xc6e00bf3",16),
    int("0xd5a79147",16),
    int("0x06ca6351",16),
    int("0x14292967",16),
    int("0x27b70a85",16),
    int("0x2e1b2138",16),
    int("0x4d2c6dfc",16),
    int("0x53380d13",16),
    int("0x650a7354",16),
    int("0x766a0abb",16),
    int("0x81c2c92e",16),
    int("0x92722c85",16),
    int("0xa2bfe8a1",16),
    int("0xa81a664b",16),
    int("0xc24b8b70",16),
    int("0xc76c51a3",16),
    int("0xd192e819",16),
    int("0xd6990624",16),
    int("0xf40e3585",16),
    int("0x106aa070",16),
    int("0x19a4c116",16),
    int("0x1e376c08",16),
    int("0x2748774c",16),
    int("0x34b0bcb5",16),
    int("0x391c0cb3",16),
    int("0x4ed8aa4a",16),
    int("0x5b9cca4f",16),
    int("0x682e6ff3",16),
    int("0x748f82ee",16),
    int("0x78a5636f",16),
    int("0x84c87814",16),
    int("0x8cc70208",16),
    int("0x90befffa",16),
    int("0xa4506ceb",16),
    int("0xbef9a3f7",16),
    int("0xc67178f2",16)
]

def get_pwd() -> str:
    """Returns the path to the working directory"""

    return run(["pwd"], capture_output=True).stdout[:-1].decode()

def as_padded_bytes(object) -> list[bytes]:
    """Converts an object into bytes with SHA padding at the end.

    Arguments:
        object : The object to convert into bytes

    Returns:
        list[bytes] : The byte array including the 10...0[len] padding.
    """
    byte_list = bytes(object)
    length = len(byte_list)

    # Append the '1' bit (int("0x80 = 10000000)
    padded = byte_list + b'\x80'

    # Pad with zeros until length ≡ 56 mod 64
    while (len(padded) % 64) != 56:
        padded += b'\x00'

    bit_length = length * 8
    padded += bit_length.to_bytes(8, byteorder='big')

    # Split into 32-bit blocks
    int_bytes = [padded[i] for i in range(len(padded))]

    return from_bytes_to_32bit_blocks(int_bytes)

def from_bytes_to_32bit_blocks(data: list[int]) -> list[int]:
    """Converts a list of bytes into a list of 32-bit numbers.

    Arguments:
        data (list[int]) : The list of 8-bit numbers.

    Returns:
        list[int] : The list of 32-bit numbers.
    """
    blocks = []
    for i in range(0, len(data), 4):
        # Using bitwise OR (|) and left shift (<<)
        block = (data[i] << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]
        blocks.append(block)
    return blocks

def build_registers():
    return [
        NUM_ROWS,
        *W,
        A, B, C, D, E, F, G, H, T1, T2,
        *BITS,
        *BITWISE_OUTPUT,
        *CARRY,
        *HASH
    ]

def set_next_block(input):
    global W
    for i in range(16):
        W[i] = input[i]

def set_input_row(input):
    global NUM_ROWS, W, HASH, A,B,C,D,E,F,G,H
    NUM_ROWS = 0

    for i in range(16):
        W[i] = input[i]
    for i in range(8):
        HASH[i] = INITIAL_HASHES[i]

    A,B,C,D,E,F,G,H = INITIAL_HASHES

def build_row(file):
    for element in build_registers():
        file.write(str(element) + " ")
    file.write("\n")


def add_padded_row(file):
    build_row(file)

def build_first_half_round(round, file):
    global NUM_ROWS, BITS, D,E,F,G,H, BITWISE_OUTPUT, T1
    NUM_ROWS += 1

    # The first 3 sets of BITS store the bitwise decomposition of e,f,g
    for index in range(32):
        BITS[index] = (E >> (31 - index)) & 1
        BITS[32 + index] = (F >> (31 - index)) & 1
        BITS[64 + index] = (G >> (31 - index)) & 1

    # Bits sets 4 and 5 store the decomposition of Sum1 and Chi while the last 2 act as carries
    for index in range(32):
        sum1 = BITS[(index - 6) % 32] + BITS[(index - 11) % 32] + BITS[(index - 25) % 32]
        chi = BITS[index] * BITS[32 + index] + (1 - BITS[index]) * BITS[64 + index]

        BITS[96 + index] = sum1 % 2
        BITS[160 + index] = sum1 // 2

        BITS[128 + index] = chi % 2
        BITS[192 + index] = chi // 2
    
    # The bitwise output stores the 32-bit equivalent
    power = pow(2, 31)
    BITWISE_OUTPUT[0] = 0
    BITWISE_OUTPUT[1] = 0
    for index in range(32):
        BITWISE_OUTPUT[0] += power * BITS[96 + index]
        BITWISE_OUTPUT[1] += power * BITS[128 + index]
        power //= 2

    # Complete the current row. This will also set the T2, A,B,C,D, CARRY values computed from the
    # previous round.
    build_row(file)
    
    # We pre-empt the values for the next row. Since the second half always follows
    # this function, we set T1, CARRY, E,F,G,H there.

    # Computing and reducing T1
    for i in range(len(CARRY)):
        CARRY[i] = 0

    if round > 15:
        T1 = H + BITWISE_OUTPUT[0] + BITWISE_OUTPUT[1] + ROUND_CONSTANTS[round] + W[15]
    else:
        T1 = H + BITWISE_OUTPUT[0] + BITWISE_OUTPUT[1] + ROUND_CONSTANTS[round] + W[round]

    index = 0
    while T1 >= LIMIT:
        CARRY[index] = 1
        T1 -= LIMIT
        index += 1
    
    # Finishing the round assignments
    H,G,F,E = G,F,E,(D + T1)

    if E >= LIMIT:
        E -= LIMIT
        CARRY[index] = 1

def build_second_half_round(file):
    global NUM_ROWS, BITS, A,B,C,D,E,F,G,H, BITWISE_OUTPUT, CARRY, T1, T2
    NUM_ROWS += 1

    # The first 3 sets of BITS store the bitwise decomposition of a,b,c
    power = pow(2, 31)
    for index in range(32):
        BITS[index] = A // power % 2
        BITS[32 + index] = B // power % 2
        BITS[64 + index] = C // power % 2
        power //=2

    # Bit sets 4 and 5 store the bitwise decomposition of Sum0 and Maj while the last 2 act as carries
    for index in range(32):
        Sum0 = BITS[(index - 2) % 32] + BITS[(index - 13) % 32] + BITS[(index - 22) % 32]
        Maj = BITS[index] * BITS[32 + index] + BITS[index] * BITS[64 + index] + BITS[32 + index] * BITS[64 + index]

        BITS[96 + index] = Sum0 % 2
        BITS[160 + index] = Sum0 // 2

        BITS[128 + index] = Maj % 2
        BITS[192 + index] = Maj // 2

    # Bitwise output stores the 32-bit equivalent
    power = pow(2, 31)
    BITWISE_OUTPUT[0] = 0
    BITWISE_OUTPUT[1] = 0
    for index in range(32):
        BITWISE_OUTPUT[0] += power * BITS[96 + index]
        BITWISE_OUTPUT[1] += power * BITS[128 + index]
        power //= 2

    # We complete the current row, this will also set T1, E,F,G,H, CARRY from the previous function
    build_row(file)

    # RESET THE CARRIES
    for i in range(len(CARRY)):
        CARRY[i] = 0

    # Computing and reducing T2
    # We pre-empt the T2, A,B,C,D, CARRY functions
    T2 = BITWISE_OUTPUT[0] + BITWISE_OUTPUT[1]

    if T2 >= LIMIT:
        CARRY[0] = 1
        T2 -= LIMIT

    D,C,B,A = C,B,A,(T1 + T2)

    if A >= LIMIT:
        CARRY[1] = 1
        A -= LIMIT

def build_message_schedule(file):
    global NUM_ROWS, W, BITS, CARRY, BITWISE_OUTPUT
    NUM_ROWS += 1

    # Temporarily copy W[0] (W_t-16)
    W16 = W[0]

    # Shift W registers 1 step
    for index in range(15):
        W[index] = W[index + 1]

    # We first decompose W_t-2 and W_t-15
    power = pow(2, 31)
    for index in range(32):
        BITS[index] = W[13] // power % 2
        BITS[32 + index] = W[0] // power % 2
        power //=2
    
    # We compute the bitwise decomposition of sigma1, sigma0
    for index in range(32):
        right_shift = BITS[32 + index - 3] if index - 3 >= 0 else 0
        right_shift2 = BITS[index - 10] if index - 10 >= 0 else 0

        Sigma0 = BITS[32 + (index - 7) % 32] + BITS[32 + (index - 18) % 32] + right_shift
        Sigma1 = BITS[(index - 17) % 32] + BITS[(index - 19) % 32] + right_shift2

        BITS[64 + index] = Sigma1 % 2
        BITS[128 + index] = Sigma1 // 2

        BITS[96 + index] = Sigma0 % 2
        BITS[160 + index] = Sigma0 // 2

    # The bitwise output registers store the 32-bit equivalent
    power = pow(2, 31)

    BITWISE_OUTPUT[0] = 0
    BITWISE_OUTPUT[1] = 0
    for index in range(32):
        BITWISE_OUTPUT[0] += power * BITS[64 + index]
        BITWISE_OUTPUT[1] += power * BITS[96 + index]
        power //= 2

    # Construct the new message schedule
    W[15] = BITWISE_OUTPUT[0] + BITWISE_OUTPUT[1] + W[8] + W16

    for index in range(10):
        CARRY[index] = 0

    index = 0
    while W[15] >= LIMIT:
        CARRY[index] = 1
        W[15] -= LIMIT
        index += 1
    
    power = pow(2, 31)
    for index in range(32):
        BITS[192 + index] = W[15] // power % 2
        power //= 2

    build_row(file)

def add_hash_update(file):
    global NUM_ROWS, HASH, A,B,C,D,E,F,G,H, CARRY
    NUM_ROWS += 1

    HASH[0] += A
    HASH[1] += B
    HASH[2] += C
    HASH[3] += D
    HASH[4] += E
    HASH[5] += F
    HASH[6] += G
    HASH[7] += H

    for index in range(8):
        CARRY[index] = HASH[index] // LIMIT
        HASH[index] = HASH[index] % LIMIT
    
    A = HASH[0]
    B = HASH[1]
    C = HASH[2]
    D = HASH[3]
    E = HASH[4]
    F = HASH[5]
    G = HASH[6]
    H = HASH[7]

    build_row(file)

def next_power_of_2(x):
    return 1 if x <= 1 else 1 << (x - 1).bit_length()

def attest_to_size(file, is_initial = False):
    global NUM_ROWS, BITS, HASH
    NUM_ROWS += 1

    registers_per_set = 24
    for set in range(8):
        for i in range(8):
            if is_initial and set == 0:
                BITS[32 + i] = HASH[i]
            elif set == 0:
                BITS[32 + i] = BITS[40 + 7 * registers_per_set + i]
            elif set != 0:
                BITS[32  + set * registers_per_set + i] = BITS[40 + (set - 1) * registers_per_set + i]
            BITS[40 + set * registers_per_set + i] = BITS[32 + set * registers_per_set + i] // 2
            BITS[48 + set * registers_per_set + i] = BITS[32 + set * registers_per_set + i] % 2
    build_row(file)

def build_trace(input, file):
    set_input_row(input[:16])

    blocks = len(input) // 16
    
    for index in range(blocks):
        # The first 16 rounds we have no schedule word update
        for round in range(16):
            build_first_half_round(round, file)
            build_second_half_round(file)

        # Store the A,B,C,D,T2,CARRY registers from previous round
        add_padded_row(file)

        # The next rounds are encoded in 4 rows each
        for round in range(16, 64):
            build_message_schedule(file)
            build_first_half_round(round, file)
            build_second_half_round(file)
            add_padded_row(file)
        add_hash_update(file)

        for _ in range(30):
            add_padded_row(file)
        
        if index + 1 != blocks:
            set_next_block(input[16 * (index + 1) : 16 * (index + 2)])

    # During the last 4 rows we attest that the hash values are indeed 32 bits
    attest_to_size(file, True)
    attest_to_size(file)
    attest_to_size(file)
    attest_to_size(file)

    for _ in range(256 * blocks, next_power_of_2(256 * blocks)):
        add_padded_row(file)

def build_trace_for_message(message, file) -> tuple[int, list[int], int, int]:
    """Benchmarks the prover.

    Arguments:
        message : The object which is being hashed
    
    Returns:
        tuple[int, list[int], int, int]:
            int: number of 512-bit blocks in the hash
            list[int]: the expected result of the trace
            int: the execution time in ns
            int: the peak memory consumption in bytes
    """
    input = as_padded_bytes(message)
    expected = from_bytes_to_32bit_blocks([byte for byte in sha256(message).digest()])

    num_blocks = len(input) / 16

    start = time.perf_counter_ns()
    tracemalloc.start()

    build_trace(input, file)

    end = time.perf_counter_ns()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return (num_blocks, expected, end - start, peak)

if __name__ == '__main__':
    # Write trace to file
    file = open(f"{get_pwd()}/data/trace_data/sha256.trace.txt", "w")
    
    message = "abc" * 40
    message = message.encode('utf-8')
    benchmarks = build_trace_for_message(message, file)
    file.close()

    # Write benchmarks
    jsonBenchmarks = {
        "NumBlocks": benchmarks[0],
        "Result": benchmarks[1],
        "Runtime": benchmarks[2],
        "Memory": benchmarks[3]
    }

    with open(f"{get_pwd()}/data/trace_data/sha256.benchmarks", "w") as file:
        dump(jsonBenchmarks, file)
