"""Test Generation System

This script reads a test configuration and generates the corresponding PKI structure.
    - CA Reuse chance is 50%.
    - If a CA is reused, the CA is randomly chosen among existing ones.
    - Otherwise a new CA is created.

Then, all the certificate chains, along with the LOAP message flow is aggregated into the DCS interface (.json document).
"""
from os.path import join, basename, splitext
from argparse import ArgumentParser
from json import load, dump
from random import randint
from subprocess import run
from glob import glob

import os

def extract_chains(tree, root_nodes):
    chains = []

    def dfs(node, path):
        # if node has no children OR is unknown key -> treat as leaf
        if node not in tree or not tree[node]:
            chains.append(path[:])
            return

        for child in tree[node]:
            dfs(child, path + [child])

    for root in root_nodes:
        dfs(root, [root])

    return chains

if __name__ == '__main__':
    print("[+] Running the Test Generation System.")
    print("[+] ===================================")

    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_false", default=True)
    args = parser.parse_args()

    print(f"[+] Debug flag: {not args.debug}")

    specs_path = os.environ["LOAP_TEST_SPECIFICATION_PATH"]
    itf_path = os.environ["LOAP_INTERFACE_PATH"]
    test_data = {}

    # Retrieve all test cases
    test_specifications = glob(join(specs_path, "*.json"))
    print(f"[+] Found {len(test_specifications)} test scenarios.")

    for test_file in test_specifications:
        print(f"[+] Reading test specification {test_file}.")
        json_data = None
        with open(test_file, "r") as file:
            json_data = load(file)

        if not json_data:
            print(f"[-] Skipping invalid test case {test_file}..")
            exit(1)

        # Extracting test parameters
        test_name = splitext(basename(test_file))[0] 
        nr_chains = int(json_data["Nr.Tests"])
    
        length_lb = int(json_data["PKIConfiguration"]["ChainLength"][0])
        length_ub = int(json_data["PKIConfiguration"]["ChainLength"][1])

        crl_lb = int(json_data["PKIConfiguration"]["RevokedCertificates"][0])
        crl_ub = int(json_data["PKIConfiguration"]["RevokedCertificates"][1])

        signatures = json_data["PKIConfiguration"]["AvailableSignatures"]
        loap_messages = []

        for message in json_data["MessageFlow"]:
            loap_messages.append({
                "Type": message["Type"],
            })

            if loap_messages[-1]["Type"] == "MessageAuthentication":
                loap_messages[-1]["Parameters"] = message["Message"]

        print(f"[+] Number of chains: {nr_chains}")
        print(f"[+] Chain length bounds: [{length_lb}, {length_ub}]")
        print(f"[+] CRL length bounds: [{crl_lb}, {crl_ub}]")
        print(f"[+] Available signatures: {signatures}")
        print(f"[+] LOAP Messages in flow: {len(loap_messages)}")

        # Resetting running variables
        nextRootIndex = 1
        nextIntermediateCAIndex = 1
        nextLeafIndex = 1

        cert_chains = {}
        
        for i in range(1, nr_chains + 1):
            print(f"[+] Generating PKI certificate chain ({i}/{nr_chains})")
            print("[+] Sampling chain parameters...")

            chain_length = randint(length_lb, length_ub)
            crl_lengths = [0]
            cert_signatures = []
            
            for _ in range(chain_length):
                cert_signatures.append(signatures[randint(0, len(signatures) - 1)])

            for _ in range(1, chain_length - 1):
                crl_lengths.append(randint(crl_lb, crl_ub))

            print(f"[+] Sampled length of chain: {chain_length}")
            print(f"[+] Sampled CRL lengths: {crl_lengths}")
            print(f"[+] Sampled Signature schemes: {cert_signatures}")

            CAName = ""
            newCA = False

            if randint(0, 1) == 0 or i == 1:
                # If we do not reuse a root or this is the first ever chain
                print(f"[+] Creating a new root CA: RootCA{nextRootIndex}...")
                run(["./scripts/create_certificate.sh", test_name, "", f"RootCA{nextRootIndex}", cert_signatures[0]], capture_output=args.debug)
                run(["./scripts/regen_crl.sh", test_name, f"RootCA{nextRootIndex}"], capture_output=args.debug)

                cert_chains[f"RootCA{nextRootIndex}"] = []
                CAName = f"RootCA{nextRootIndex}"
                nextRootIndex += 1
                newCA = True
            else:
                CAName = f"RootCA{randint(1, nextRootIndex - 1)}"
            
            # Generate intermediate CAs
            for cert_index in range(1, chain_length - 1):
                if newCA or randint(0, 1) == 0:
                    cert_chains[CAName].append(f"IntermediateCA{nextIntermediateCAIndex}")
                    cert_chains[f"IntermediateCA{nextIntermediateCAIndex}"] = []

                    # Once we create a new CA, we commit to an entire new chain (no more reuse)
                    print(f"[+] Creating a new intermediate CA: IntermediateCA{nextIntermediateCAIndex}...")
                    run(["./scripts/create_certificate.sh", test_name, f"{CAName}", f"IntermediateCA{nextIntermediateCAIndex}", cert_signatures[cert_index], "true"], capture_output=args.debug)
                    CAName = f"IntermediateCA{nextIntermediateCAIndex}"
                    newCA = True
                    nextIntermediateCAIndex += 1

                    print(f"[+] Creating CA CRL...")
                    for _ in range(crl_lengths[cert_index]):
                        run(["./scripts/revoke_cert.sh", test_name, CAName], capture_output=args.debug)
                    run(["./scripts/regen_crl.sh", test_name, f"{CAName}"], capture_output=args.debug)
                else:
                    # We reuse a CA at this level
                    candidates = [x for x in cert_chains[CAName] if x.startswith("IntermediateCA")]
                    
                    if candidates != []:
                        CAName = candidates[randint(0, len(candidates) - 1)]
                    else:
                        # We have no candidate CA for reuse, force creation.
                        cert_chains[CAName].append(f"IntermediateCA{nextIntermediateCAIndex}")
                        cert_chains[f"IntermediateCA{nextIntermediateCAIndex}"] = []

                        # Once we create a new CA, we commit to an entire new chain (no more reuse)
                        print(f"[+] Creating a new intermediate CA: IntermediateCA{nextIntermediateCAIndex}...")
                        run(["./scripts/create_certificate.sh", test_name, f"{CAName}", f"IntermediateCA{nextIntermediateCAIndex}", cert_signatures[cert_index], "true"], capture_output=args.debug)
                        CAName = f"IntermediateCA{nextIntermediateCAIndex}"
                        newCA = True
                        nextIntermediateCAIndex += 1

                        print(f"[+] Creating CA CRL...")
                        for _ in range(crl_lengths[cert_index]):
                            run(["./scripts/revoke_cert.sh", test_name, CAName], capture_output=args.debug)
                        run(["./scripts/regen_crl.sh", test_name, f"{CAName}"], capture_output=args.debug)

            # Generate leaf
            print(f"[+] Creating a new leaf: Leaf{nextLeafIndex}")
            run(["./scripts/create_certificate.sh", test_name, f"{CAName}", f"Leaf{nextLeafIndex}", cert_signatures[-1]], capture_output=args.debug)

            cert_chains[CAName].append(f"Leaf{nextLeafIndex}")
            nextLeafIndex += 1

        # Generating Test Data for the Data Collection System
        print("[+] Updated interface for Data Collection System...")
        root_CAs = [x for x in cert_chains.keys() if x.startswith("RootCA")]
        cert_chain_data = extract_chains(cert_chains, root_CAs)

        test_data[test_name] = {
            "CertificateChains": cert_chain_data,
            "MessageFlow": loap_messages
        }
    
    print("[+] Writing interface for Data Collection System...")
    with open(f"{itf_path}/dcs.json", "w") as file:
        dump(test_data, file)
