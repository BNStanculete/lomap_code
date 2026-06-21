import math

FIELD_MODULUS = pow(2, 251) + 17 * pow(2, 192) + 1

BLOWUP_FACTOR = 4
LOG_BLOWUP = 2
LOG_HEIGHT = 20
A = 16

DMAX = pow(2, LOG_HEIGHT + 4)

ELL = 3 / ((1 / BLOWUP_FACTOR) - (6 / pow(2, LOG_HEIGHT + LOG_BLOWUP)))

E1 = ELL / FIELD_MODULUS
E2 = (DMAX + pow(2, LOG_HEIGHT) + A) * pow(ELL, 2) / (FIELD_MODULUS - A *  pow(2, LOG_HEIGHT + LOG_BLOWUP) - pow(2, LOG_HEIGHT))
E3 = pow(3.5, 7) * pow(pow(2, LOG_HEIGHT + LOG_BLOWUP), 2) / (3 * pow(1 / BLOWUP_FACTOR, 1.5) * FIELD_MODULUS)
EI = E3 / 2 + (7 * (pow(2, LOG_HEIGHT + LOG_BLOWUP) + 1) * pow(2, LOG_HEIGHT)) / (math.sqrt(1 / BLOWUP_FACTOR) * FIELD_MODULUS)

FINAL = math.sqrt(1 /BLOWUP_FACTOR) * (1 + 1/6)
TARGET = pow(2, -129)

maximum = max(E1, E2, E3, EI)

assert maximum <= TARGET

QUERIES = 1
result = FINAL

while result > TARGET:
    result *= FINAL
    QUERIES += 1

print(f"Required queries for blowupfactor {BLOWUP_FACTOR}: {QUERIES}")