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

    return int_bytes

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

def next_power_of_two(number: int) -> int:
    """Computes the next power of two that is >= the provided number.

    Arguments:
        number (int) : The number
    
    Returns:
        int : The power of two that is >= number.
    """
    power_of_two = 1

    while power_of_two < number:
        power_of_two *= 2
    return power_of_two