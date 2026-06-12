# Copyright Bogdan Stanculete 2026. All Rights Reserved.

FIELD_MODULUS = pow(2, 251) + 17 * pow(2, 192) + 1

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

def get_modular_inverse(number: int, modulus: int = FIELD_MODULUS) -> int:
    def extended_gcd(a: int, b: int):
        if b == 0:
            return a, 1, 0

        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    gcd, x, _ = extended_gcd(number, modulus)

    if gcd != 1:
        raise ValueError(
            f"Modular inverse does not exist for {number} modulo {modulus}"
        )

    return x % modulus

class RegisterView:
    def __init__(self, *registers):
        self.registers = registers
        self.flat_map = []  # maps global index -> (reg, local index)
        self.__length = 0

        for reg, start, length in registers:
            self.__length += length
            
            for i in range(length):
                self.flat_map.append((reg, start + i))
        
        self.total_size = len(self.flat_map)

    def __getitem__(self, i):
        reg, j = self.flat_map[i]
        return reg[j]

    def __setitem__(self, i, value):
        reg, j = self.flat_map[i]
        reg[j] = value

    def __len__(self):
        return self.__length