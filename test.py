from prover.trace_builders.serializer.crl_builder import CrlTraceBuilder
from datetime import datetime, timezone

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
    issuer = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["Issuer"]
    revocation_data = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["RevokedSerials"]

    oid_value_pairs = []
    pair = {
        "OID": "",
        "Value": ""
    }

    for index, item in enumerate(issuer.split("=")):        
        if index % 2 == 0:
            pair["OID"] = item
        else:
            pair["Value"] = item
            oid_value_pairs.append(pair)
            pair = {
                "OID": "",
                "Value": ""
            }

    parsed_rev_data = []
    for item in revocation_data:
        date = datetime.strptime(item["Date"], "%a %b %d %H:%M:%S %Y")
        date = date.replace(tzinfo=timezone.utc)
        date = date.strftime("%y%m%d%H%M%SZ")

        parsed_rev_data.append(
            (item["SerialNumber"], date)
        )


    this_update = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["ThisUpdate"]
    next_update = data["TestCase1"]["LOAPProver"]["CRLUpdate1"]["CRLFields"]["NextUpdate"]

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = x509.load_pem_x509_crl(raw)
    der_raw = raw.public_bytes(serialization.Encoding.DER)

    # TODO: Move this conversion in pre-processing
    this_update = datetime.strptime(this_update, "%a %b %d %H:%M:%S %Y")
    this_update = this_update.replace(tzinfo=timezone.utc)
    this_update = this_update.strftime("%y%m%d%H%M%SZ")

    next_update = datetime.strptime(next_update, "%a %b %d %H:%M:%S %Y")
    next_update = next_update.replace(tzinfo=timezone.utc)
    next_update = next_update.strftime("%y%m%d%H%M%SZ")

    builder = CrlTraceBuilder("./trace.txt")
    builder.set_input(serial, algo, signature, public_key, oid_value_pairs, (this_update, next_update), parsed_rev_data, der_raw)
    builder.build_trace(False)
