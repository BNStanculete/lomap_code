"""This script evaluates certificate chains and yields the baseline metrics.
"""
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from json import load, dump
from math import log2, ceil
from subprocess import run
from pathlib import Path
from os.path import join
import tracemalloc
import time
import os

def start_measurement():
    tracemalloc.start()
    return time.perf_counter_ns()

def stop_measurement():
    tracemalloc.stop()
    return time.perf_counter_ns()

if __name__ == '__main__':
    print("[+] Running the PKI Verifier...")
    print("[+] ===================================")
    itf_path = os.environ["LOAP_INTERFACE_PATH"]
    res_path = os.environ["LOAP_RESULTS_PATH"]
    temp_path = os.environ["LOAP_RUNTIME_PATH"]

    test_data = None
    with open(f"{itf_path}/tes.json", "r") as file:
        test_data = load(file)
    
    if not test_data:
        print("[-] Invalid or TES json file.")
        print("[-] Maybe there was an error during the earlier steps?")
        exit(1)

    # Running state
    root_cns = []
    metrics = {}
    tested_flows = {
        "Authentication": 0,
        "CRLUpdate": 0,
        "MessageAuthentication": 0
    }

    nr_testcases = len(test_data.keys())
    print(f"[+] Discovered {nr_testcases} test cases.")

    for test in test_data.keys():
        print(f"[+] Processing test case {test}...")
        print(f"[+] Found {len(test_data[test]["Flow"])} interactions.")
        print("[+] Loading prover certificate...")

        prover_CN = next((certificate for certificate in test_data[test]["PKIVerifier"].keys() if certificate.startswith("Leaf")), None)
        prover_certificate_path = test_data[test]["PKIVerifier"][prover_CN]["Certificate"]

        if test_data[test]["TestSuite"] not in metrics.keys():
            root_cns = []
            metrics[test_data[test]["TestSuite"]] = {
                "Authentication": {
                    "CPU": [0, 0, 0],
                    "RAM": [0, 0, 0],
                    "BW": [0, 0, 0],
                    "CACHE": [0, 0, 0],
                },
                "CRLUpdate": {
                    "CPU": [0, 0, 0],
                    "RAM": [0, 0, 0],
                    "BW": [0, 0, 0],
                },
                "MessageAuthentication": {
                    "CPU": [0, 0, 0],
                    "RAM": [0, 0, 0],
                    "BW": [0, 0, 0],
                },
                "TrustStore": 0
            }
            tested_flows[test_data[test]["TestSuite"]] = {
                "Authentication": 0,
                "CRLUpdate": 0,
                "MessageAuthentication": 0
            }

        prover_certificate = None
        with open(prover_certificate_path, "rb") as file:
            prover_certificate = file.read()
        prover_certificate = x509.load_pem_x509_certificate(prover_certificate)

        
        root_CN = next((certificate for certificate in test_data[test]["PKIVerifier"].keys() if certificate.startswith("Root")), None)
        if root_CN not in root_cns:
            print("[+] Updating trust store size...")
            root_cns.append(root_CN)
            root_path = Path(test_data[test]["PKIVerifier"][root_CN]["Certificate"])
            metrics[test_data[test]["TestSuite"]]["TrustStore"] += root_path.stat().st_size

        for message in test_data[test]["Flow"]:
            # Retrieve auxiliary parameters from the LOAPProver (e.g. message signature)
            auxiliary_params = test_data[test]["LOAPProver"][message]

            if message.startswith("Authentication"):
                print("[+] Validating the full certificate chain...")
                intermediates = [certificate for certificate in test_data[test]["PKIVerifier"].keys() if certificate.startswith("Intermediate")]
                tested_flows[test_data[test]["TestSuite"]]["Authentication"] += 1
                crls = []

                print("[+] Constructing shell command...")
                command = [
                    "/usr/bin/time", "-v",
                    "openssl", "verify", "-CAfile", test_data[test]["PKIVerifier"][root_CN]["Certificate"],
                ]

                for intermediateCA in intermediates:
                    command.append("-untrusted")
                    command.append(test_data[test]["PKIVerifier"][intermediateCA]["Certificate"])
                    crls.append(test_data[test]["PKIVerifier"][intermediateCA]["RevocationList"])
                crls.append(test_data[test]["PKIVerifier"][prover_CN]["RevocationList"])
                command.extend(["-CRLfile", join(temp_path, f"{test}_all.crl"), "-crl_check_all", prover_certificate_path])

                # Ensure temporary directory exists
                os.makedirs(join(temp_path, "loap"), exist_ok=True)

                print("[+] Bundling CRLs...")
                with open(join(temp_path, f"{test}_all.crl"), "wb") as file:            
                    for crl_file in crls:
                        with open(crl_file, "rb") as in_file:
                            file.write(in_file.read())

                print("[+] Running the verification...")
                now = start_measurement()
                result = run(command, capture_output=True, text=True)
                elapsed = stop_measurement()

                print("[+] Extracting metrics...")
                start_index = result.stderr.find("Maximum resident set size (kbytes): ")
                length = len("Maximum resident set size (kbytes): ")
                stop_index = start_index + length + result.stderr[start_index + length:].find("\n")

                memory_in_KB = int(result.stderr[start_index + length : stop_index])
                bw = 0
                cache = 0

                # Measure BW and cache size
                for key in test_data[test]["PKIVerifier"]:
                    cert_size = Path(test_data[test]["PKIVerifier"][key]["Certificate"]).stat().st_size
                    crl_size = Path(test_data[test]["PKIVerifier"][key]["RevocationList"]).stat().st_size \
                        if test_data[test]["PKIVerifier"][key]["RevocationList"] != "" else 0

                    # We send both cert and CRL, but cache only the certificates
                    bw += cert_size + crl_size
                    cache += cert_size

                print(f"[+] Updating Metrics...")
                metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][2] += (elapsed - now) / 1000000000
                metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][2] += memory_in_KB * 1024
                metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][2] += bw
                metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][2] += cache

                metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][1], (elapsed - now) / 1000000000)
                metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][1], memory_in_KB * 1024)
                metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][1], bw)
                metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][1], cache)

                if metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][0] = (elapsed - now) / 1000000000
                else:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"][0], (elapsed - now) / 1000000000)

                if metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][0] = memory_in_KB * 1024
                else:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"][0], memory_in_KB * 1024)

                if metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][0] = bw
                else:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"][0], bw)

                if metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][0] = cache
                else:
                    metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"][0], cache)

                print(f"[+] Perf counter: {(elapsed - now) / 1000000000:.4f} seconds")
                print(f"[+] Peak memory: {memory_in_KB * 1024} bytes")
            elif message.startswith("CRLUpdate"):
                tested_flows[test_data[test]["TestSuite"]]["CRLUpdate"] += 1
                print("[+] Verifying non-revocation against CRL...")

                command = [
                    "/usr/bin/time", "-v",
                    "openssl", "verify", "-CAfile", test_data[test]["PKIVerifier"][prover_CN]["SignedBy"],
                                         "-CRLfile", test_data[test]["PKIVerifier"][prover_CN]["RevocationList"],
                                         "-crl_check", test_data[test]["PKIVerifier"][prover_CN]["Certificate"]
                ]

                now = start_measurement()
                result = run(command, capture_output=True, text=True)
                elapsed = stop_measurement()

                print("[+] Extracting metrics...")
                start_index = result.stderr.find("Maximum resident set size (kbytes): ")
                length = len("Maximum resident set size (kbytes): ")
                stop_index = start_index + length + result.stderr[start_index + length:].find("\n")

                memory_in_KB = int(result.stderr[start_index + length : stop_index])
                bw = Path(test_data[test]["PKIVerifier"][prover_CN]["RevocationList"]).stat().st_size

                print(f"[+] Updating Metrics...")
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][2] += (elapsed - now) / 1000000000
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][2] += memory_in_KB * 1024
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][2] += bw

                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][1], (elapsed - now) / 1000000000)
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][1], memory_in_KB * 1024)
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][1], bw)

                if metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][0] = (elapsed - now) / 1000000000
                else:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"][0], (elapsed - now) / 1000000000)

                if metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][0] = memory_in_KB * 1024
                else:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"][0], memory_in_KB * 1024)

                if metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][0] = bw
                else:
                    metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"][0], bw)

            elif message.startswith("MessageAuthentication"):
                print("[+] Verifying message signature...")
                tested_flows[test_data[test]["TestSuite"]]["MessageAuthentication"] += 1

                # Start measurement
                now = start_measurement()

                if len(test_data[test]["LOAPProver"][message]["Signature"]) == 1:
                    prover_certificate.public_key().verify(
                        test_data[test]["LOAPProver"][message]["Signature"][0].to_bytes(
                            prover_certificate.public_key().key_size // 8,
                            byteorder = "big"
                        ),
                        test_data[test]["LOAPProver"][message]["Message"].encode("utf-8"),
                        padding.PKCS1v15(),
                        prover_certificate.signature_hash_algorithm)
                else:
                    prover_certificate.public_key().verify(
                        utils.encode_dss_signature(
                            test_data[test]["LOAPProver"][message]["Signature"][0],
                            test_data[test]["LOAPProver"][message]["Signature"][1]),
                        test_data[test]["LOAPProver"][message]["Message"].encode("utf-8"),
                        ec.ECDSA(prover_certificate.signature_hash_algorithm))

                # Stop measurement
                elapsed = stop_measurement()

                # Update metrics
                signature_size = 0
                for number in test_data[test]["LOAPProver"][message]["Signature"]:
                    signature_size += ceil(log2(number)) // 8

                print("[+] Updating baseline metrics...")
                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][2] += ((elapsed - now) / 1000000000.0)
                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][2] += tracemalloc.get_traced_memory()[1]
                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][2] +=                                       \
                    len(test_data[test]["LOAPProver"][message]["Message"]) +                                            \
                    signature_size

                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][1], (elapsed - now) / 1000000000.0)
                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][1], tracemalloc.get_traced_memory()[1])
                metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][1] = \
                    max(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][1], len(test_data[test]["LOAPProver"][message]["Message"]) + signature_size)

                if metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][0] = (elapsed - now) / 1000000000.0
                else:
                    metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["CPU"][0], (elapsed - now) / 1000000000.0)

                if metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][0] == 0:
                        metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][0] = tracemalloc.get_traced_memory()[1]
                else: 
                    metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["RAM"][0], tracemalloc.get_traced_memory()[1])

                if metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][0] == 0:
                    metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][0] = len(test_data[test]["LOAPProver"][message]["Message"]) + signature_size
                else:
                    metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][0] = \
                        min(metrics[test_data[test]["TestSuite"]]["MessageAuthentication"]["BW"][0], len(test_data[test]["LOAPProver"][message]["Message"]) + signature_size)
            else:
                print("[-] Invalid message type for ", message)
    
    # Aggregate metrics
    print("[+] Computing final averages...")
    for suite in metrics.keys():
        for key in metrics[suite].keys():
            if key == "TrustStore":
                continue

            for metric_key in metrics[suite][key].keys():
                if tested_flows[suite][key] == 0:
                    continue
                metrics[suite][key][metric_key][2] /= tested_flows[suite][key]
    
    print("[+] Storing baseline metrics...")
    with open(f"{res_path}/baseline.json", "w") as file:
        dump(metrics, file)
