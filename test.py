from prover.trace_builders.serializer.crl_builder import CrlTraceBuilder
from prover.trace_builders.serializer import CertificateTraceBuilder
from prover.trace_builders.utils import FIELD_MODULUS
from cryptography.hazmat.primitives import serialization
from cryptography import x509

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

    input_data = data["TestCase1"]["LOAPProver"]["Authentication1"]
    proof_data = {}
    for key in input_data["Certificates"].keys():
        if key in input_data["CRLs"].keys():
            proof_data[key] = {
                "Certificate": input_data["Certificates"][key],
                "CRL": {
                    "CRLFields": input_data["CRLs"][key],
                    "ProverSerial": 0,
                    "PublicKey": [],
                },
                "NextInChain": ""
            }
    
    print(f"[+] Connecting logical components of proof...")
    for key in proof_data.keys():
        for name_part in proof_data[key]["Certificate"]["Issuer"]:
            if name_part["OID"] == "CN" and name_part["Value"] != key:
                proof_data[key]["NextInChain"] = name_part["Value"]

        next_in_chain = proof_data[key]["NextInChain"]
        if next_in_chain != '':
            proof_data[key]["Certificate"]["IssuerPublicKey"] = proof_data[next_in_chain]["Certificate"]["PublicKey"]

    key = [x for x in input_data["Certificates"].keys() if x.startswith("Leaf")]
    proof_data["ProverCertificate"] = {
        "Certificate": input_data["Certificates"][key[0]],
        "CRL": None,
        "NextInChain": ""
    }
    
    for name_part in proof_data["ProverCertificate"]["Certificate"]["Issuer"]:
        if name_part["OID"] == "CN":
            proof_data["ProverCertificate"]["NextInChain"] = name_part["Value"]

    next_in_chain = proof_data["ProverCertificate"]["NextInChain"]
    proof_data["ProverCertificate"]["Certificate"]["IssuerPublicKey"] = proof_data[next_in_chain]["Certificate"]["PublicKey"]
    
    for index, key in enumerate(proof_data.keys()):
        next_in_chain = proof_data[key]["NextInChain"]

        if next_in_chain != '':
            proof_data[next_in_chain]["CRL"]["ProverSerial"] = proof_data[key]["Certificate"]["Serial"]
            proof_data[next_in_chain]["CRL"]["PublicKey"] = proof_data[next_in_chain]["Certificate"]["PublicKey"]

    raw = None
    with open(proof_data["RootCA1"]["CRL"]["CRLFields"]["Path"], "rb") as file:
        raw = file.read()
    raw = x509.load_pem_x509_crl(raw)
    raw = raw.public_bytes(serialization.Encoding.DER)

    builder = CrlTraceBuilder("./trace.txt")
    # print(proof_data["IntermediateCA1"]["Certificate"])
    # builder = CertificateTraceBuilder("./trace.txt")
    builder.set_input(proof_data["RootCA1"]["CRL"])
    builder.build_trace(False)

    # assert raw[4:len(builder.get_raw()) + 4] == builder.get_raw(), f"{raw[4:len(builder.get_raw()) + 4]} vs {builder.get_raw()}"