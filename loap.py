"""This script builds the required STARK traces & proofs.
"""
from json import load, dump
from pathlib import Path
from os.path import join
import tracemalloc
import time
import os

from subprocess import run
from prover.trace_builders.serializer import CrlTraceBuilder
from prover.trace_builders.serializer import AuthenticationTraceBuilder

from poseidon_py import poseidon_hash

STARK_PROVER_EXECUTABLE_PATH = join(Path(__file__).resolve().parent,        \
                                    "prover/stark_provers/target/release/loap_stark")

PROVER_MEMORY_MASK = "Maximum resident set size (kbytes): "
PROVER_TIME_MASK = "[+] Proof finalization took "
PROOF_SIZE_MASK = "[+] Proof size: "

VERIFIER_TIME_MASK = "[+] Verification took "
VERIFIER_MEMORY_MASK = "[+] Heap used during verification: "

def toggle_measurement():
    tracemalloc.start()
    return time.perf_counter_ns()

def extract_metric(output: str, mask: str):
    start_index = output.find(mask)
    length = len(mask)
    stop_index = start_index + length + output[start_index + length:].find("\n")

    while output[start_index + length : stop_index][-1] not in "0123456789":
        stop_index -= 1

    return float(output[start_index + length : stop_index])

def write_ets_nodes(message_block: list[str]) -> int:
    index = 0
    cache_bytes = 0
    trust_store_bytes = 0

    # Last element is the prover commitment
    while index < len(message_block):
        entity_cn = message_block[index]

        if Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcert")).exists():
            index += 7

            if not entity_cn.startswith("Root"):
                cache_bytes += Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcert")).stat().st_size
        else:
            print(f"[+] Writing ETS Node {entity_cn + '.loapcert'}")
            with open(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcert"), "w") as file:
                for _ in range(7):
                    file.write(message_block[index])
                    file.write("\n")
                    index += 1

            if entity_cn.startswith("Root"):
                trust_store_bytes += Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcert")).stat().st_size
            else:
                cache_bytes += Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcert")).stat().st_size

        if index < len(message_block):
            next_cn = message_block[index]
            if next_cn == entity_cn:
                if Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcrl")).exists():
                    index += 4
                    cache_bytes += Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcrl")).stat().st_size
                else:
                    print(f"[+] Writing CRL ETS Node {entity_cn + '.loapcrl'}")
                    with open(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcrl"), "w") as file:
                        for _ in range(4):
                            file.write(message_block[index])
                            file.write("\n")
                            index += 1
                    cache_bytes += Path(join(os.environ["LOAP_ETS_PATH"], entity_cn + ".loapcrl")).stat().st_size
        return (cache_bytes, trust_store_bytes)

def get_poseidon_blocks(list):
    hashable_blocks = []
    for item in list:
        bytes_obj = item.encode('utf-8')
        int_obj = int.from_bytes(bytes_obj)

        subblocks = len(bytes_obj) // 128 + 1
        for i in range(subblocks):
            hashable_blocks.append((int_obj >> (128 * subblocks - i - 1)) & (1 << 128 - 1))
    return hashable_blocks


if __name__ == '__main__':
    print("[+] Running the LOAP Prover...")
    print("[+] ===================================")
    itf_path = os.environ["LOAP_INTERFACE_PATH"]
    res_path = os.environ["LOAP_RESULTS_PATH"]
    temp_path = os.environ["LOAP_RUNTIME_PATH"]

    # Ensure temporary directory exists
    os.makedirs(join(temp_path, "proofs"), exist_ok=True)
    os.makedirs(join(temp_path, "ets"), exist_ok=True)

    # Preset the command for the Winterfell prover and verifier
    STARK_CRL_COMMAND = [
        "/usr/bin/time", "-v",
        STARK_PROVER_EXECUTABLE_PATH, "crlupdate",
    ]

    STARK_AUTH_COMMAND = [
        "/usr/bin/time", "-v",
        STARK_PROVER_EXECUTABLE_PATH, "auth"
    ]

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
    print(f"[+] Initializaing the trace builders...")

    CRLUpdateBuilder = CrlTraceBuilder(join(temp_path, "proofs", "trace.txt"))
    AuthenticationBuilder = AuthenticationTraceBuilder(join(temp_path, "proofs", "trace.txt"))

    for test in test_data.keys():
        print(f"[+] Processing test case {test}...")
        print(f"[+] Found {len(test_data[test]["Flow"])} interactions.")

        if test_data[test]["TestSuite"] not in metrics.keys():
            metrics[test_data[test]["TestSuite"]] = {
                "Authentication": {
                    "CPU": 0,
                    "RAM": 0,
                    "BW": 0,
                    "CACHE": 0,
                },
                "CRLUpdate": {
                    "Prover": {
                        "CPU": 0,
                        "RAM": 0,
                    },
                    "CPU": 0,
                    "RAM": 0,
                    "BW": 0,
                },
                "MessageAuthentication": {
                    "CPU": 0,
                    "RAM": 0,
                    "BW": 0,
                },
                "TrustStore": 0
            }

        for message in test_data[test]["Flow"]:
            print(f"[+] Loading prover inputs...")
            input_data = test_data[test]["LOAPProver"][message]

            if message.startswith("Authentication"):
                tested_flows["Authentication"] += 1
                print(f"[+] Executing proofs and verification for {message}")
                print(f"[+] Grouping CA certificates with CRLs...")
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
                    else:
                        proof_data[key]["Certificate"]["IssuerPublicKey"] = proof_data[key]["Certificate"]["PublicKey"]

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

                ets_nodes = []
                print(f"[+] Writing prover message...")
                with open(join(temp_path, "message.txt"), "w") as file:
                    message = []
                    for key in proof_data.keys():
                        message_block = []

                        for oid_part in proof_data[key]["Certificate"]["Subject"]:
                            if oid_part["OID"] == "CN":
                                message_block.append(oid_part["Value"])
                        for oid_part in proof_data[key]["Certificate"]["Issuer"]:
                            if oid_part["OID"] == "CN":
                                message_block.append(oid_part["Value"])

                        message_block.append(str(poseidon_hash.poseidon_hash(proof_data[key]["Certificate"]["Serial"], 0)))

                        # Hash the public key
                        pk_blocks = [
                            proof_data[key]["Certificate"]["PublicKey"][0]]
                        pk_blocks.extend([
                            (proof_data[key]["Certificate"]["PublicKey"][1] >> shift) & (1 << 128 - 1) for shift in range(1920, -1, -128)
                        ])

                        pk_hash = poseidon_hash.poseidon_hash_many(pk_blocks)
                        message_block.append(str(pk_hash))

                        message_block.append(proof_data[key]["Certificate"]["NotBefore"])
                        message_block.append(proof_data[key]["Certificate"]["NotAfter"])

                        # Hash the cert representative
                        cert_hash = poseidon_hash.poseidon_hash_many(
                            get_poseidon_blocks(message_block)
                        )

                        message_block.append(str(cert_hash))
                        
                        # Now deal with the CRL
                        if proof_data[key]["CRL"] != None:
                            crl_block = [
                                message_block[0],
                                proof_data[key]["CRL"]["CRLFields"]["ThisUpdate"],
                                proof_data[key]["CRL"]["CRLFields"]["NextUpdate"],
                            ]

                            crl_hash = poseidon_hash.poseidon_hash_many(
                                get_poseidon_blocks(crl_block)
                            )

                            crl_block.append(str(crl_hash))
                            message_block.extend(crl_block)
                        
                        message.extend(message_block)

                        # Write block to file
                        for item in message_block:
                            file.write(item)
                            file.write("\n")

                        # Write block to ets
                        print("[+] Updating the ETS...")
                        cache, trust_store = write_ets_nodes(message_block)

                        print("[+] Accumulating CACHE and TrustStore metrics...")
                        metrics[test_data[test]["TestSuite"]]["TrustStore"] += trust_store
                        metrics[test_data[test]["TestSuite"]]["Authentication"]["CACHE"] += cache

                    # Hash the block
                    block_hash = poseidon_hash.poseidon_hash_many(
                        get_poseidon_blocks(message)
                    )                

                    file.write(str(block_hash))
                    file.write("\n")
                start_ns = toggle_measurement()

                print("[+] Building STARK trace...")
                for index, key in enumerate(proof_data.keys()):
                    next_in_chain = proof_data[key]["NextInChain"]

                    if next_in_chain != '':
                        proof_data[next_in_chain]["CRL"]["ProverSerial"] = proof_data[key]["Certificate"]["Serial"]
                        proof_data[next_in_chain]["CRL"]["PublicKey"] = proof_data[next_in_chain]["Certificate"]["PublicKey"]
                AuthenticationBuilder.set_input(proof_data)
                AuthenticationBuilder.build_trace(False)

                print("[+] Building & Verifying STARK proof...")
                result = run(STARK_AUTH_COMMAND, capture_output=True, text=True)
                stop_ns = toggle_measurement()

                print(f"[+] Separating prover & verifier metrics...")
                prover_memory_kb = extract_metric(result.stderr, PROVER_MEMORY_MASK)
                prover_time_sec = extract_metric(result.stdout, PROVER_TIME_MASK)
                proof_size_bytes = extract_metric(result.stdout, PROOF_SIZE_MASK)

                verifier_memory_bytes = extract_metric(result.stdout, VERIFIER_MEMORY_MASK)
                verifier_time_ms = extract_metric(result.stdout, VERIFIER_TIME_MASK)

                print(f"[+] Aggregating metrics...")
                metrics[test_data[test]["TestSuite"]]["Authentication"]["Prover"]["CPU"] += prover_time_sec
                metrics[test_data[test]["TestSuite"]]["Authentication"]["Prover"]["RAM"] += prover_memory_kb + (tracemalloc.get_traced_memory()[1] / 1024.0)
                metrics[test_data[test]["TestSuite"]]["Authentication"]["CPU"] += verifier_time_ms
                metrics[test_data[test]["TestSuite"]]["Authentication"]["RAM"] += verifier_memory_bytes
                metrics[test_data[test]["TestSuite"]]["Authentication"]["BW"] += proof_size_bytes

                print(f"[+] Cleaning up...")
                os.remove(join(temp_path, "proofs", "trace.txt"))


            elif message.startswith("CRLUpdate"):
                tested_flows["CRLUpdate"] += 1
                print(f"[+] Executing proofs and verification for {message}")
                print(f"[+] Writing prover message...")
                with open(join(temp_path, "message.txt"), "w") as file:
                    # Public Key against which CRL is verified
                    cn = ""
                    for oid_part in input_data["CRLFields"]["Issuer"]:
                        if oid_part["OID"] == "CN":
                            cn = input_data["CRLFields"]["Issuer"][0]["Value"]
                            file.write(input_data["CRLFields"]["Issuer"][0]["Value"])
                            file.write("\n")

                    file.write(input_data["CRLFields"]["ThisUpdate"])
                    file.write("\n")

                    file.write(input_data["CRLFields"]["NextUpdate"])
                    file.write("\n")

                    # Write the Poseidon hash
                    hash = poseidon_hash.poseidon_hash_many([
                        int.from_bytes(cn.encode("utf-8")),
                        int.from_bytes(input_data["CRLFields"]["ThisUpdate"].encode("utf-8")),
                        int.from_bytes(input_data["CRLFields"]["NextUpdate"].encode("utf-8"))
                    ])

                    file.write(str(hash))
                    file.write("\n")

                start_ns = toggle_measurement()

                print("[+] Building STARK trace...")
                CRLUpdateBuilder.set_input(input_data)
                CRLUpdateBuilder.build_trace(in_memory=False)

                print("[+] Building & Verifying STARK proof...")
                result = run(STARK_CRL_COMMAND, capture_output=True, text=True)
                stop_ns = toggle_measurement()

                print(f"[+] Separating prover & verifier metrics...")
                prover_memory_kb = extract_metric(result.stderr, PROVER_MEMORY_MASK)
                prover_time_sec = extract_metric(result.stdout, PROVER_TIME_MASK)
                proof_size_bytes = extract_metric(result.stdout, PROOF_SIZE_MASK)

                verifier_memory_bytes = extract_metric(result.stdout, VERIFIER_MEMORY_MASK)
                verifier_time_ms = extract_metric(result.stdout, VERIFIER_TIME_MASK)

                print(f"[+] Aggregating metrics...")
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["Prover"]["CPU"] += prover_time_sec
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["Prover"]["RAM"] += prover_memory_kb + (tracemalloc.get_traced_memory()[1] / 1024.0)
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["CPU"] += verifier_time_ms
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["RAM"] += verifier_memory_bytes
                metrics[test_data[test]["TestSuite"]]["CRLUpdate"]["BW"] += proof_size_bytes

                print(f"[+] Cleaning up...")
                os.remove(join(temp_path, "proofs", "trace.txt"))

    print("[+] Normalizing metrics...")
    for test_suite in metrics.keys():
        for message in metrics[test_suite].keys():
            if message == "TrustStore":
                continue
            if tested_flows[message] == 0:
                continue

            for key in metrics[test_suite][message].keys():
                if key == "Prover":
                    metrics[test_suite][message][key]["CPU"] /= tested_flows[message]
                    metrics[test_suite][message][key]["RAM"] /= tested_flows[message]
                else:
                    metrics[test_suite][message][key] /= tested_flows[message]

    print("[+] Writing metrics to file...")
    with open(f"{res_path}/loap.json", "w") as file:
        dump(metrics, file)
