from math import ceil, log2

def OID2Hex(oid: str) -> str:
    hex_output = '0x'

    arcs = oid.split('.')
    first_number = int(arcs[0]) * 40 + int(arcs[1])
    hex_output += f"{first_number:02x}"

    for arc in arcs[2:]:
        digits = []
        arc = int(arc)

        if arc == 0:
            digits.insert(0,0)
        else:
            while arc > 0:
                digits.insert(0, arc % 128)
                arc //= 128
        
        for d in digits[:-1]:
            hex_output += f"{d | 0x80:02x}"
        hex_output += f"{digits[-1]:02x}"

    return hex_output

def BuildTL(tag: int, length: int) -> int:
    """Starting from a tag, constructs the TL header of a TLV field
    """
    tl = tag

    # Add the length
    if length < 128:
        tl <<= 8
        tl |= length
    else:
        nr_bytes = ceil(ceil(log2(length)) / 8)

        tl <<= 8
        tl |= (0x80 | nr_bytes)
        tl <<= (8 * nr_bytes)
        tl |= length
    return tl