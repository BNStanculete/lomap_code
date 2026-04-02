# Copyright Bogdan Stanculete 2026. All Rights Reserved.

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

class RegisterView:
    def __init__(self, *registers):
        self.registers = registers
        self.flat_map = []  # maps global index -> (reg, local index)

        for reg, start, length in registers:
            for i in range(length):
                self.flat_map.append((reg, start + i))
        
        # Precompute cumulative offsets
        # self.offsets = []
        # total = 0
        # for _, _, length in registers:
        #     self.offsets.append(total)
        #     total += length
        self.total_size = len(self.flat_map)

    # def _locate(self, i):
    #     if i < 0 or i >= self.total_size:
    #         raise IndexError("Register index out of range")
        
    #     # Find which register this index belongs to
    #     for (reg, start, length), offset in zip(self.registers, self.offsets):
    #         print(i, offset, length)
    #         if i < offset + length:
    #             return reg, i + start - offset

    def __getitem__(self, i):
        reg, j = self.flat_map[i]
        return reg[j]

    def __setitem__(self, i, value):
        reg, j = self.flat_map[i]
        reg[j] = value