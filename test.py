from prover.trace_builders.serializer.crl_builder import CrlTraceBuilder
from prover.trace_builders.utils import FIELD_MODULUS

def extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0

    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

if __name__ == '__main__':
    import os
    tes_path = os.environ["LOAP_INTERFACE_PATH"]

    from json import load
    data = None
    with open(f'{tes_path}/tes.json', 'r') as file:
        data = load(file)

    builder = CrlTraceBuilder("./trace.txt")
    builder.set_input(data["TestCase1"]["LOAPProver"]["CRLUpdate1"])
    # builder.togglePadding()
    builder.build_trace(False)
