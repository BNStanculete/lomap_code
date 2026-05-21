from prover.trace_builders.serializer.crl_builder import CrlTraceBuilder

if __name__ == '__main__':
    import os
    tes_path = os.environ["LOAP_INTERFACE_PATH"]

    from json import load
    data = None
    with open(f'{tes_path}/tes.json', 'r') as file:
        data = load(file)
    
    raw = None
    with open(data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["Path"], "rb") as file:
        raw = file.read()
    
    signature = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["Signature"]
    algo = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["SignatureAlgorithm"]
    serial = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["ProverSerial"]
    public_key = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["PublicKey"]

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = x509.load_pem_x509_crl(raw)
    der_raw = raw.public_bytes(serialization.Encoding.DER)

    builder = CrlTraceBuilder("./trace.txt")
    builder.set_input(serial, algo, signature, public_key, der_raw)
    builder.build_trace(False)
