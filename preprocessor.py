"""This script represents the Data Collection System

It parses the TGS interface JSON, and acts in the following way:
    1. Each certificate chain becomes a test case
    2. For each test case:
        2.1. Builds the PKI simulator data. It retrieves the certificates and CRLs and
        structures them in the following format:
            "PKIVerifier" : {
                "LeafCertificate1" : {
                    "Path": [PATH_TO_CERT],
                    "SignedBy": [PATH_TO_CA_CERT],
                    "RevocationList": [PATH_TO_CRL],
                    "NextInChain": [CA_COMMON_NAME]
                }

                "IntermediateCA1" : {
                    "Path": ...
                    "SignedBy": ...
                    "RevocationList": ...
                    "NextInChain": ...
                }
            }
        
        2.2. Using the above format it extracts the relevant certificate fields for the LOAP prover;
        NOTE: The extracted fields depend on the current message in the flow. As such, this step is repeated
        for each message in the MessageFlow
            "LOAPProver": {
                "Authentication": {
                    "LeafCertificate1": {
                        "Version": 3,
                        "Serial": ...,
                        "Issuer": ...,
                        ...
                    },
                    "IntermediateCA1": {
                        ...
                    }
                }
                
                "MessageAuthentication1": {
                    "Message": ...,
                    "Signature": ....,
                    "Public Key": ....,
                },
            }
    3. All this data is aggregated into the TES interface, which is also a .json document.
"""
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from json import load, dump
from os.path import join

from datetime import datetime, timezone

import os
import asn1crypto.x509 as asn1
import asn1crypto.crl as asn1crl

from asn1crypto.pem import unarmor

def process_public_key(public_key):
    """Returns the public key numbers as a list of integers.

    This is needed so the prover can generate the signature verification STARK.
    """

    if hasattr(public_key, "public_numbers"):
        numbers = public_key.public_numbers()

        if hasattr(public_key, "curve"):
            return [numbers.x, numbers.y]
        else:
            return [numbers.e, numbers.n]
    return None

def parse_subject_field(subject: str) -> list[dict]:
    """Splits a subject field into a pair of X.509 items.

    e.g. C=NL/CN=CA gets split into [
        {"OID": "C", "Value": "NL"}, {"OID": "CN", "Value": "CA"}
    ]
    
    Arguments:
        subject (str): The one-liner string, as yielded by the function `rfc4514_string()`

    Returns:
        list[dict]: The parsed list of OID-Value pairs
    """
    oid_value_pairs = []
    pair = {
        "OID": "",
        "Value": ""
    }

    for name_pair in subject.split(','):
        for index, item in enumerate(name_pair.split("=")):        
            if index % 2 == 0:
                pair["OID"] = item
            else:
                pair["Value"] = item
                oid_value_pairs.append(pair)
                pair = {
                    "OID": "",
                    "Value": ""
                }
    return oid_value_pairs

def convert_time_field(time: str) -> str:
    """Converts local UTC time into X.509 format.
    
    Arguments:
        time (str): local UTC time, as extracted from the X.509 object

    Returns:
        str: A serialization-ready representation
    """
    result = datetime.strptime(time, "%a %b %d %H:%M:%S %Y")
    result = result.replace(tzinfo=timezone.utc)

    return result.strftime("%y%m%d%H%M%SZ")

def get_object_extensions(object_path: str, is_certificate: bool) -> bytes:
    raw = None

    with open(object_path, "rb") as file:
        raw = file.read()

    _, _, der_data = unarmor(raw)

    if not is_certificate:
        crl_obj = asn1crl.CertificateList.load(der_data)
        tbs = crl_obj["tbs_cert_list"]

        if "crl_extensions" in tbs:
            return "".join(str(tbs["crl_extensions"].dump()))
    else:
        cert_obj = asn1.Certificate.load(der_data)
        tbs = cert_obj["tbs_certificate"]

        if "extensions" in tbs:
            return "".join(str(tbs["extensions"].dump()))
    return ""

def get_object_lengths(object_path: str, is_certificate: bool = False) -> list[int]:
    """Parses and X.509 object and extracts
        - tbsCertificate length
        - subject length (if present)
        - issuer length (if present)
        - revoked serials length (if present)
    
    Arguments:
        object_path (str): The path to the PEM certificate / CRL.

    Returns:
        list[int]: A list of the extracted lengths, in that order.    
    """
    extracted_lengths = []
    raw = None

    with open(object_path, "rb") as file:
        raw = file.read()

    _, _, der_data = unarmor(raw)

    if not is_certificate:
        crl_obj = asn1crl.CertificateList.load(der_data)
        tbs = crl_obj["tbs_cert_list"]

        extracted_lengths = [
            len(tbs.dump()),
            len(tbs["issuer"].contents)
        ]

        issuer_lengths = []
        for rdn in tbs["issuer"].chosen:
            issuer_lengths.append([len(rdn.contents), len(rdn[0].contents)])
        issuer_lengths.reverse()

        for item in issuer_lengths:
            extracted_lengths.append(item[0])
            extracted_lengths.append(item[1])

        revoked = tbs["revoked_certificates"]

        extracted_lengths.append(
            len(revoked.contents) if revoked.native is not None else 0
        )

        if revoked:
            for serial in revoked:
                extracted_lengths.append(len(serial.contents))
    else:
        cert_obj = asn1.Certificate.load(der_data)
        tbs = cert_obj["tbs_certificate"]

        extracted_lengths = [
            len(tbs.dump()),
            len(tbs["issuer"].contents),
        ]

        issuer_lengths = []
        for rdn in tbs["issuer"].chosen:
            issuer_lengths.append([len(rdn.contents), len(rdn[0].contents)])
        issuer_lengths.reverse()

        for item in issuer_lengths:
            extracted_lengths.append(item[0])
            extracted_lengths.append(item[1])

        extracted_lengths.append(len(tbs["subject"].contents))

        subject_lengths = []
        for rdn in tbs["subject"].chosen:
            subject_lengths.append([len(rdn.contents), len(rdn[0].contents)])
        subject_lengths.reverse()

        for item in subject_lengths:
            extracted_lengths.append(item[0])
            extracted_lengths.append(item[1])

    return extracted_lengths

if __name__ == '__main__':
    print("[+] Running the Data Collection System.")
    print("[+] ===================================")

    itf_path = os.environ["LOAP_INTERFACE_PATH"]
    pki_path = os.environ["LOAP_PKI_PATH"]

    # Parse the TGS interface
    tgs_interface_data = None
    with open(f"{itf_path}/dcs.json", "r") as file:
        tgs_interface_data = load(file)

    if not tgs_interface_data:
        print(f"[-] Could not read `{itf_path}/tgs.json`.")
        print("[-] Maybe an error occured during test generation?")
        exit(1)
    
    # Running state
    tes_interface = {}
    nextTestID = 1
    nextMessageAuthentication = 1
    nextAuthentication = 1
    nextUpdate = 1

    # Parse tests
    for test_file in tgs_interface_data.keys():
        nr_chains = len(tgs_interface_data[test_file]["CertificateChains"])
        nr_flows = len(tgs_interface_data[test_file]["MessageFlow"])

        print(f"[+] Processing test suite {test_file}...")
        print(f"[+] Discovered {nr_chains} certificate chains.")
        print(f"[+] Discovered {nr_flows} LOAP interactions.")

        for index, certificate_chain in enumerate(tgs_interface_data[test_file]["CertificateChains"]):
            print(f"[+] Processing certificate chain... ({index + 1} / {nr_chains})")
            tes_interface[f"TestCase{nextTestID}"] = {
                "TestSuite": test_file,
                "PKIVerifier": {},
                "LOAPProver": {},
                "Flow": []
            }

            # Build the PKI verifier data
            certificate_path = f"{pki_path}/{test_file}/"
            issuer_path = f"{pki_path}/{test_file}/"
            
            print("[+] Collecting data for the PKI Verifier...")
            for index, certificate in enumerate(certificate_chain):
                print("[+] Processing certificate ", certificate)
                certificate_path = join(certificate_path, certificate)

                tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate] = {}
                tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["Certificate"] = join(certificate_path, "certificate.pem")
                tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["PrivateKey"] = join(certificate_path, "private", "private_key.pem")
                print("[+] Calculated certificate path: ", tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["Certificate"])
                
                if index == 0:
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["SignedBy"] = ""
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["RevocationList"] = ""
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["NextInChain"] = ""

                    print("[+] Done for root CA.")
                else:
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["SignedBy"] = join(issuer_path, "certificate.pem")
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["RevocationList"] = join(issuer_path, "crl", "latest_crl.pem")
                    tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["NextInChain"] = certificate_chain[index - 1]

                    print("[+] Calculated issuing CA certificate path: ", tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["SignedBy"])
                    print("[+] Calculated relevant CRL path: ", tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["RevocationList"])
                    print("[+] Calculated CN of certificate up in chain: ", tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][certificate]["NextInChain"])

                issuer_path = certificate_path
                certificate_path = join(certificate_path, "newcerts")

            print("[+] Verifying certificate and CRL paths...")
            test_case_skipped = False
            
            for key in tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"].keys():
                with open(tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["PrivateKey"], "rb") as file:
                    if not file.readable():
                        print(f"[-] Private Key {tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["PrivateKey"]} is unreadable or doesn't exist.")
                        print(f"[-] Maybe there was an error during test generation?")
                        print(f"[-] Removing test case...")
                        del tes_interface[f"TestCase{nextTestID}"]
                        test_case_skipped = 1
                        break

                with open(tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["Certificate"], "rb") as file:
                    if not file.readable():
                        print(f"[-] Certificate {tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["Certificate"]} is unreadable or doesn't exist.")
                        print(f"[-] Maybe there was an error during test generation?")
                        print(f"[-] Removing test case...")
                        del tes_interface[f"TestCase{nextTestID}"]
                        test_case_skipped = 1
                        break
                
                if tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["RevocationList"] != "":
                    with open(tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["RevocationList"], "rb") as file:
                        if not file.readable():
                            print(f"[-] CRL {tes_interface[f"TestCase{nextTestID}"]["PKIVerifier"][key]["RevocationList"]} is unreadable or doesn't exist.")
                            print(f"[-] Maybe there was an error during test generation?")
                            print(f"[-] Removing test case...")
                            del tes_interface[f"TestCase{nextTestID}"]
                            test_case_skipped = 1
                            break

            if test_case_skipped:
                continue

            print("[+] Collecting data for the LOAP Prover (Step 1) ...")
            for index, msg in enumerate(tgs_interface_data[test_file]["MessageFlow"]):
                print(f"[+] Processing interaction... ({index + 1} / {nr_flows})")

                if msg["Type"] == "MessageAuthentication":
                    tes_interface[f"TestCase{nextTestID}"]["Flow"].append(f"MessageAuthentication{nextMessageAuthentication}")
                    tes_interface[f"TestCase{nextTestID}"]["LOAPProver"][f"MessageAuthentication{nextMessageAuthentication}"] = {
                        "Message": msg["Parameters"],
                        "Signature": "",
                        "PublicKey": [],
                        "SignatureAlgorithm": ""
                    }
                    nextMessageAuthentication += 1
                elif msg["Type"] == "CRLUpdate":
                    tes_interface[f"TestCase{nextTestID}"]["Flow"].append(f"CRLUpdate{nextUpdate}")
                    tes_interface[f"TestCase{nextTestID}"]["LOAPProver"][f"CRLUpdate{nextUpdate}"] = {
                        "CRLFields": {},
                        "ProverSerial": "",
                        "PublicKey": [],
                    }
                    nextUpdate += 1
                elif msg["Type"] == "Authentication":
                    tes_interface[f"TestCase{nextTestID}"]["Flow"].append(f"Authentication{nextAuthentication}")
                    tes_interface[f"TestCase{nextTestID}"]["LOAPProver"][f"Authentication{nextAuthentication}"] = {}
                    nextAuthentication += 1
            nextTestID += 1

    # Part 2 of data collection: reading CRLs and certificates and extracting semantically-relevant fields.
    # Here, the message signatures are also computed for MessageAuthentication type flows
    print("[+] Collecting data for the LOAP prover (Step 2) ...")
    for index, test_case in enumerate(tes_interface.keys()):
        print(f"[+] Processing test case nr. {index + 1} ...")       
        prover_CN = next((certificate for certificate in tes_interface[test_case]["PKIVerifier"].keys() if certificate.startswith("Leaf")), None)
        prover_pk = None
        prover_certificate = None

        for message in tes_interface[test_case]["Flow"]:
            print(f"[+] Processing interaction {message} ...")

            if message.startswith("MessageAuthentication"):
                if not prover_pk:
                    print("[+] Loading prover private key...")
                    prover_pk_path = tes_interface[test_case]["PKIVerifier"][prover_CN]["PrivateKey"]
                    with open(prover_pk_path, "rb") as file:
                        prover_pk = file.read()
                    prover_pk = load_pem_private_key(prover_pk, password=None)

                print("[+] Signing message with prover's private key...")
                try:
                    signature = prover_pk.sign(
                        tes_interface[test_case]["LOAPProver"][message]["Message"].encode("utf-8"),
                        padding.PKCS1v15(),
                        hashes.SHA256())
                    signature = [int(signature.hex(), 16)]
                    tes_interface[test_case]["LOAPProver"][message]["SignatureAlgorithm"] = "1.2.840.113549.1.1.11"
                except TypeError:
                    signature = prover_pk.sign(
                        tes_interface[test_case]["LOAPProver"][message]["Message"].encode("utf-8"),
                        ec.ECDSA(hashes.SHA256()))
                    signature = utils.decode_dss_signature(signature)
                    tes_interface[test_case]["LOAPProver"][message]["SignatureAlgorithm"] = "1.2.840.10045.4.3.2"

                print("[+] Completing TES interface data...")
                tes_interface[test_case]["LOAPProver"][message]["Signature"] = signature
                tes_interface[test_case]["LOAPProver"][message]["PublicKey"] = process_public_key(prover_pk.public_key())

                if not tes_interface[test_case]["LOAPProver"][message]["PublicKey"]:
                    print("[-] Invalid signature scheme for public key.")
                    print("[-] Maybe there was an error during test generation?")
                    print("[-] Removing test case...")
                    del tes_interface[test_case]
                    continue

            elif message.startswith("CRLUpdate"):
                print("[+] Retrieving prover certificate and issuing CA CRL...")
                prover_certificate_path = tes_interface[test_case]["PKIVerifier"][prover_CN]["Certificate"]
                issuing_CA_CRL = tes_interface[test_case]["PKIVerifier"][prover_CN]["RevocationList"]
                issuing_CA_cert = tes_interface[test_case]["PKIVerifier"][prover_CN]["SignedBy"]

                if not prover_certificate:
                    print("[+] Loading prover certificate...")
                    with open(prover_certificate_path, "rb") as file:
                        prover_certificate = file.read()
                    prover_certificate = x509.load_pem_x509_certificate(prover_certificate)
                lengths = get_object_lengths(issuing_CA_CRL)

                # Populating prover serial and CA public key
                tes_interface[test_case]["LOAPProver"][message]["ProverSerial"] = prover_certificate.serial_number

                print("[+] Loading CA certificate...")
                ca_certificate = None
                with open(issuing_CA_cert, "rb") as file:
                    ca_certificate = file.read()
                ca_certificate = x509.load_pem_x509_certificate(ca_certificate)
                tes_interface[test_case]["LOAPProver"][message]["PublicKey"] = process_public_key(ca_certificate.public_key())

                print("[+] Loading CRL...")
                crl = None
                with open(issuing_CA_CRL, "rb") as file:
                    crl = file.read()
                crl = x509.load_pem_x509_crl(crl)

                print("[+] Extracting CRL fields...")
                tes_interface[test_case]["LOAPProver"][message]["Path"] = issuing_CA_CRL
                tes_interface[test_case]["LOAPProver"][message]["CRLFields"] = {
                    "TBSLength": lengths[0],
                    "Version": 1,
                    "IssuerLength": lengths[1],
                    "Issuer": parse_subject_field(crl.issuer.rfc4514_string()),
                    "SignatureAlgorithm": crl.signature_algorithm_oid.dotted_string,
                    "Signature": [int(crl.signature.hex(), 16)] if crl.signature_algorithm_oid._name.find("RSA") != -1 else utils.decode_dss_signature(crl.signature),
                    "ThisUpdate": convert_time_field(crl.last_update_utc.ctime()),
                    "NextUpdate": convert_time_field(crl.next_update_utc.ctime()),
                    "RevokedSerials": [
                        {
                            "SerialNumber": rev.serial_number,
                            "Date": convert_time_field(rev.revocation_date_utc.ctime())
                        } for rev in crl
                    ],
                }

                tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["Extensions"] = \
                    get_object_extensions(issuing_CA_CRL, False)

                index = 2
                for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["Issuer"]):
                    tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["Issuer"][idx]["Length"] = lengths[index]
                    tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["Issuer"][idx]["SubLength"] = lengths[index+1]
                    index += 2
                tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["RevokedLength"] = lengths[index]
                index += 1

                for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["RevokedSerials"]):
                    tes_interface[test_case]["LOAPProver"][message]["CRLFields"]["RevokedSerials"][idx]["Length"] = lengths[index]
                    index += 1
 
            elif message.startswith("Authentication"):
                print("[+] Collecting Chain Data...")
                next_in_chain = prover_CN

                tes_interface[test_case]["LOAPProver"][message]["Certificates"] = {}
                tes_interface[test_case]["LOAPProver"][message]["CRLs"] = {}

                while next_in_chain != "":
                    certificate = None
                    crl = None
                    
                    print("[+] Loading certificate...")
                    with open(tes_interface[test_case]["PKIVerifier"][next_in_chain]["Certificate"], "rb") as file:
                        certificate = file.read()
                    certificate = x509.load_pem_x509_certificate(certificate)
                    lengths = get_object_lengths(tes_interface[test_case]["PKIVerifier"][next_in_chain]["Certificate"], True)
                    
                    print("[+] Updating parameters...")
                    tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain] = {
                        "Path": tes_interface[test_case]["PKIVerifier"][next_in_chain]["Certificate"],
                        "TBSLength": lengths[0],
                        "Version": 2,
                        "Serial": certificate.serial_number,
                        "SignatureAlgorithm": certificate.signature_algorithm_oid.dotted_string,
                        "Signature": [int(certificate.signature.hex(), 16)] if certificate.signature_algorithm_oid._name.find("RSA") != -1 else utils.decode_dss_signature(certificate.signature),
                        "IssuerLength": lengths[1],
                        "Issuer": parse_subject_field(certificate.issuer.rfc4514_string()),
                        "NotBefore": convert_time_field(certificate.not_valid_before_utc.ctime()),
                        "NotAfter": convert_time_field(certificate.not_valid_after_utc.ctime()),
                        "Subject": parse_subject_field(certificate.subject.rfc4514_string()),
                        "PublicKeyAlgorithm": certificate.public_key_algorithm_oid.dotted_string,
                        "PublicKey": process_public_key(certificate.public_key()),
                        "Extensions": {
                            "BasicConstraints": (lambda bc: {
                                "CA": bc.ca
                            }) (certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value),
                            "KeyUsage": (lambda ku: {
                                "digital_signature": ku.digital_signature,
                                "content_commitment": ku.content_commitment,
                                "key_encipherment": ku.key_encipherment,
                                "data_encipherment": ku.data_encipherment,
                                "key_agreement": ku.key_agreement,
                                "key_cert_sign": ku.key_cert_sign,
                                "crl_sign": ku.crl_sign,
                            }) (certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value)
                        }
                    }

                    tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["ExtensionsRaw"] = \
                        get_object_extensions(tes_interface[test_case]["PKIVerifier"][next_in_chain]["Certificate"], True)

                    index = 2
                    for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Issuer"]):
                        tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Issuer"][idx]["Length"] = lengths[index]
                        tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Issuer"][idx]["SubLength"] = lengths[index+1]
                        index += 2
                    tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["SubjectLength"] = lengths[index]
                    index += 1

                    for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Subject"]):
                        tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Subject"][idx]["Length"] = lengths[index]
                        tes_interface[test_case]["LOAPProver"][message]["Certificates"][next_in_chain]["Subject"][idx]["SubLength"] = lengths[index+1]
                        index += 2


                    if tes_interface[test_case]["PKIVerifier"][next_in_chain]["RevocationList"] != "":
                        print("[+] Loading CRL...")
                        with open(tes_interface[test_case]["PKIVerifier"][next_in_chain]["RevocationList"], "rb") as file:
                            crl = file.read()
                        crl = x509.load_pem_x509_crl(crl)

                        crl_issuer = tes_interface[test_case]["PKIVerifier"][next_in_chain]["NextInChain"]
                        lengths = get_object_lengths(tes_interface[test_case]["PKIVerifier"][next_in_chain]["RevocationList"])

                        tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer] = {
                            "Path": tes_interface[test_case]["PKIVerifier"][next_in_chain]["RevocationList"],
                            "TBSLength": lengths[0],
                            "Version": 1,
                            "SignatureAlgorithm": crl.signature_algorithm_oid.dotted_string,
                            "IssuerLength": lengths[1],
                            "Issuer": parse_subject_field(crl.issuer.rfc4514_string()),
                            "Signature": [int(crl.signature.hex(), 16)] if crl.signature_algorithm_oid._name.find("RSA") != -1 else utils.decode_dss_signature(crl.signature),
                            "ThisUpdate": convert_time_field(crl.last_update_utc.ctime()),
                            "NextUpdate": convert_time_field(crl.next_update_utc.ctime()),
                            "RevokedSerials": [
                                {
                                    "SerialNumber": rev.serial_number,
                                    "Date": convert_time_field(rev.revocation_date_utc.ctime())
                                } for rev in crl
                            ],
                        }
                        tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["Extensions"] = \
                            get_object_extensions(tes_interface[test_case]["PKIVerifier"][next_in_chain]["RevocationList"], False)

                        index = 2
                        for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["Issuer"]):
                            tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["Issuer"][idx]["Length"] = lengths[index]
                            tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["Issuer"][idx]["SubLength"] = lengths[index+1]
                            index += 2
                        tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["RevokedLength"] = lengths[index]
                        index += 1

                        for idx, item in enumerate(tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["RevokedSerials"]):
                            tes_interface[test_case]["LOAPProver"][message]["CRLs"][crl_issuer]["RevokedSerials"][idx]["Length"] = lengths[index]
                            index += 1

                    next_in_chain = tes_interface[test_case]["PKIVerifier"][next_in_chain]["NextInChain"]


    # Save TES interface
    print("[+] Writing TES Interface...")
    with open(f"{itf_path}/tes.json", "w") as file:
        dump(tes_interface, file)
