from prover.trace_builders.serializer.crl_builder import CrlTraceBuilder

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
