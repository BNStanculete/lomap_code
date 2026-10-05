
def get_poseidon_blocks(list):
    hashable_blocks = []
    for item in list:
        bytes_obj = item.encode('utf-8')
        int_obj = int.from_bytes(bytes_obj)

        subblocks = len(bytes_obj) // 128 + 1
        for i in range(subblocks):
            hashable_blocks.append((int_obj >> (128 * subblocks - i - 1)) & (1 << 128 - 1))
    return hashable_blocks
