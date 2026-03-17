from json import load, JSONDecodeError, dump
from subprocess import run

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

import time
import tracemalloc

from os.path import getsize

import logging
import argparse
import sys
import glob

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger

def get_pwd() -> str:
    """Returns the path to the working directory"""
    print("PWD: ", run(["pwd"], capture_output=True).stdout[:-1])

    return run(["pwd"], capture_output=True).stdout[:-1].decode()

def clean_test_environment():
    logger = get_logger("TESTENV")
    pwd = get_pwd()

    cert_data = glob.glob(f"{pwd}/data/certificates/*")
    trust_store = glob.glob(f"{pwd}/data/trust_stores/lomap/*")
    lomap_store = glob.glob(f"{pwd}/results/trust_stores/lomap/*")

    rets = [
        run(["rm", "-rf", *cert_data]),
        run(["rm", "-rf", *trust_store]),
        run(["rm", "-rf", *lomap_store])
    ]

    for ret in rets:        
        if ret.returncode != 0:
            logger.error("Failed to clean test environment. Aborting tests..")
            exit(1)

def setup_test_environment(test_file: str) -> tuple[bool, dict, dict, dict]:
    """Parses a test configuration to construct the certificate chains.

    Arguments:
        test_file (str) : A path to the test configuration file.

    Returns:
        bool : The environment was initialized successfully
        dict : A dictionary mapping root CA CN to root CA directory
        dict : A dictionary mapping intermmediate CA CN to CA directory
        dict : A dictionary mapping certificate CN to certificate directory  
    """
    logger = get_logger("TESTENV")
    logger.debug(f"Parsing configuration file {test_file}")
    pwd = get_pwd()
    failed_return = (False, {}, {}, {})

    jsonConfig = None
    try:
        with open(test_file, "r") as file:
            jsonConfig = load(file)
    except JSONDecodeError as err:
        logger.error(f"Invalid test configuration file {test_file}. Aborting test case.")
        logger.debug(err.msg)
        jsonConfig = None

    if not jsonConfig:
        return failed_return
    
    try:
        numRoots = jsonConfig["Num_Roots"]
        cert_paths = {}
        root_paths = {}
        ca_paths = {}

        logger.info(f"Initializing {numRoots} root CAs.")
        for i in range(numRoots):
            root_name = "RootCA" + str(i)
            root_paths[root_name] = f"{pwd}/data/certificates/{root_name}/"
            
            ret = run([f"{pwd}/scripts/create_root.sh", root_name])
            if ret.returncode != 0:
                logger.error(f"Failed creating root CA {root_name}. Aborting test case.")

                # Clean environment
                clean_test_environment()
                return failed_return                
            
            # Build empty CRL for roots.
            ret = run([f"{pwd}/scripts/regen_crl.sh", root_paths[root_name]])
            if ret.returncode != 0:
                logger.error(f"Failed in generating the CRL. Aborting test case.")
                clean_test_environment()

                return failed_return

        for chain in jsonConfig["Chains"]:
            root_name = "RootCA" + str(chain["RootID"])

            for ca in chain["CAs"]:
                ca_name = ca["CN"]
                ca_algo = ca["Algorithm"]

                ca_paths[ca_name] = root_paths[root_name] + f"newcerts/{ca_name}/"
                logger.info(f"Creating intermediate CA {ca_name} with algorithm {ca_algo} under {root_name}.")

                ret = run([f"{pwd}/scripts/create_authority.sh", root_name, ca_name])
                if ret.returncode != 0:
                    logger.error(f"Failed creating intermmediate CA {ca_name}. Aborting test case.")

                    clean_test_environment()
                    return failed_return

                num_revoked = ca["RevokedCertificates"]
                logger.info(f"Creating CRL for CA {ca_name} with {num_revoked} entries.")

                for i in range(num_revoked):
                    ret = run([f"{pwd}/scripts/issue_cert.sh", ca_paths[ca_name], "Revoked" + str(i)])                    
                    if ret.returncode != 0:
                        logger.error(f"Failed in creating a certificate for revocation purposes. Aborting test case.")
                        clean_test_environment()

                        return failed_return

                    ret = run([f"{pwd}/scripts/revoke_cert.sh", ca_paths[ca_name], "Revoked" + str(i)])
                    if ret.returncode != 0:
                        logger.error(f"Failed in revoking a certificate. Aborting test case.")
                        clean_test_environment()

                        return failed_return

                ret = run([f"{pwd}/scripts/regen_crl.sh", ca_paths[ca_name]])
                if ret.returncode != 0:
                    logger.error(f"Failed in generating the CRL. Aborting test case.")
                    clean_test_environment()

                    return failed_return
                
                logger.info(f"Issuing valid certificates for CA {ca_name}.")
                for cert in ca["ValidCertificates"]:
                    cn = cert["CN"]
                    algo = cert["Algorithm"]

                    cert_paths[cn] = ca_paths[ca_name] + f"newcerts/{cn}/"

                    ret = run([f"{pwd}/scripts/issue_cert.sh", ca_paths[ca_name], cn])                    
                    if ret.returncode != 0:
                        logger.error(f"Failed in creating a certificate for revocation purposes. Aborting..")
                        clean_test_environment()

                        return failed_return
            return (True, root_paths, ca_paths, cert_paths)
    except KeyError as err:
        logger.error(f"Invalid JSON key {err.args}. Aborting test case.")

        # Clean environment
        clean_test_environment()
        return failed_return
    
def get_certificate(cert_path: str) -> x509.Certificate:
    """Loads a certificate from a given path.
    
    Arguments:
        cert_path (str) : The path to the certificate

    Returns:
        x509.Certificate : The parsed certificate bytes.
    """
    data = None
    with open(cert_path, "rb") as file:
        data = file.read()

    if not data:
        return None

    return x509.load_pem_x509_certificate(data, default_backend())

def get_crl(crl_path: str) -> x509.CertificateRevocationList:
    """Loads a CRL from a given path.
    
    Arguments:
        crl_path (str) : The path to the CRL

    Returns:
        x509.CertificateRevocationList : The parsed CRL bytes.
    """
    data = None
    with open(crl_path, "rb") as file:
        data = file.read()

    if not data:
        return None
    

    # 205 x 90 x 42

    return x509.load_pem_x509_crl(data, default_backend())

def verify_certificate(certificate: x509.Certificate, ca_certificate: x509.Certificate = None, crl: x509.CertificateRevocationList = None) -> bool:
    """Verifies a certificate for validity and non-expiration (excluding time interval).

    Arguments:
        certificate (x509.Certificate)
        ca_certificate (x509.Certificate)
        crl (x509.CertificateRevocationList)

    Returns:
        bool : Denotes if the certificate is valid and not revoked.
    """
    if certificate.issuer != ca_certificate.subject:
        return False
    
    try:
        ca_certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
    except Exception:
        return False
    
    # Verify CRL
    try:
        ca_certificate.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
    except Exception:
        return False
    
    revoked = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)

    if revoked:
        return False
    return True

def get_cn(name) -> str:
    """Converts a issuer / subject field to common name string

    Arguments:
        name : The issuer / subject field of a x509.Certificate

    Returns:
        str : the common name of the field
    """
    return name.rdns[-1].rfc4514_string()[3:]

def get_cert_chains(cert_paths: dict[str, str], ca_paths: dict[str, str], root_paths: dict[str, str]) -> tuple[list, list, list]:
    """Constructs a list of certificate chains.

    For each CA in the chain, the function pairs the CA with their corresponding CRL in a tuple.

    Arguments:
        cert_paths (dict[str, str]): A dictionary mapping certificate common names to their path in the test env.
        ca_paths (dict[str, str]): A dictionary mapping CA common names to their path in the test env.
        root_paths (dict[str, str]): A dictionary mapping root CA common names to their path in the test env.

    Returns:
        list : A list of all valid certificate chains
        list : The total chain size of each chain
        list : The total cache sizes for each chain
    """
    
    chainObjects = []
    sizes = []
    cache_sizes = []

    for cert_name in cert_paths.keys():
        size = 0
        cache = 0
        certificate = get_certificate(cert_paths[cert_name] + f"/{cert_name}.cert.pem")
        
        size += getsize(cert_paths[cert_name] + f"/{cert_name}.cert.pem")
        cache += getsize(cert_paths[cert_name] + f"/{cert_name}.cert.pem")
        
        chain = [certificate]

        if not certificate:
            logger.error(f"Invalid certificate with CN {cert_name}.")
            clean_test_environment()
            exit(1)

        # Traverse chain to get intermediate CAs
        current_issuer = get_cn(certificate.issuer)
        while not current_issuer.startswith('RootCA'):
            ca = get_certificate(ca_paths[current_issuer] + f"/certs/ca.cert.pem")
            crl = get_crl(ca_paths[current_issuer] + f"/crl/ca.crl.pem")

            size += getsize(ca_paths[current_issuer] + f"/certs/ca.cert.pem")
            cache += getsize(ca_paths[current_issuer] + f"/certs/ca.cert.pem")
            
            size += getsize(ca_paths[current_issuer] + f"/crl/ca.crl.pem")

            chain.append((ca, crl))
            current_issuer = get_cn(ca.issuer)

        # Get root certificate and CRL
        certificate = get_certificate(root_paths[current_issuer] + f"/certs/ca.cert.pem")
        crl = get_crl(root_paths[current_issuer] + f"/crl/ca.crl.pem")

        size += getsize(root_paths[current_issuer] + f"/certs/ca.cert.pem")
        cache += getsize(root_paths[current_issuer] + f"/certs/ca.cert.pem")
        
        size += getsize(root_paths[current_issuer] + f"/crl/ca.crl.pem")

        chain.append((certificate, crl))
        chainObjects.append(chain)
        
        sizes.append(size)
        cache_sizes.append(cache)

    return (chainObjects, sizes, cache_sizes)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog = "LOMAP Test Runner",
        description = "Runs a LOMAP test case",
        epilog = "")
    
    parser.add_argument('test_file', help = "The path to the test specification.")
    logger = get_logger('TESTRUNNER')

    args = parser.parse_args()

    success, root_paths, ca_paths, cert_paths = setup_test_environment(args.test_file)
    pwd = get_pwd()

    if not success:
        exit(1)

    logger.info("Converting trust store to LOMAP format.")
    ret = run(["python3", f"{pwd}/utils/converter.py", f"{pwd}/data/trust_stores/lomap", "-o", f"{pwd}/results/trust_stores/lomap"])
    if ret.returncode != 0:
        logger.error("Cannot convert trust store into LOMAP format.")
        
        clean_test_environment()
        exit(1)
    
    # Collect chain data
    logger.info("Collecting certificate chains")
    chains, sizes, cache_sizes = get_cert_chains(cert_paths, ca_paths, root_paths)

    # Run PKI verifier
    logger.info("Running the PKI benchmarks")
    pki_benchmarks = {
        "TestCases": 0,
        "Runtime": 0,               # ns
        "Memory": 0,                # bytes
        "Bandwidth": sum(sizes),    # bytes
        "Storage": sum(cache_sizes) # bytes
    }

    for chain in chains:
        pki_benchmarks["TestCases"] += 1

        # Runtime benchmark
        start = time.perf_counter_ns()
        
        # Verify leaf
        verify_certificate(chain[0], chain[1][0], chain[1][1])

        # Verify intermmediate CAs
        for i in range(1, len(chain) - 1):
            verify_certificate(chain[i][0], chain[i+1][0], chain[i+1][1])
        
        # Verify root CA
        chain[-1][0].public_key().verify(
            chain[-1][0].signature,
            chain[-1][0].tbs_certificate_bytes,
            padding.PKCS1v15(),
            chain[-1][0].signature_hash_algorithm
        )
        
        end = time.perf_counter_ns()
        pki_benchmarks["Runtime"] += (end - start)

        # Memory benchmark
        tracemalloc.start()

        # Verify leaf
        verify_certificate(chain[0], chain[1][0], chain[1][1])

        # Verify intermmediate CAs
        for i in range(1, len(chain) - 1):
            verify_certificate(chain[i][0], chain[i+1][0], chain[i+1][1])
        
        # Verify root CA
        chain[-1][0].public_key().verify(
            chain[-1][0].signature,
            chain[-1][0].tbs_certificate_bytes,
            padding.PKCS1v15(),
            chain[-1][0].signature_hash_algorithm
        )

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        pki_benchmarks["Memory"] += peak

    # Build proofs
    logger.info("Building trace files.")
    

    logger.info("Building STARK proofs.")

    # Run LOMAP verifier
    logger.info("Collecting LOMAP benchmarks.")


    # Build metrics
    metrics = {
        "Proving Time": {
            "NaivePKI": 0,
            "LOMAP": 0,
            "Improvement": 0,
            "Unit": "ms"
        },

        "Verification Time": {
            "NaivePKI": pki_benchmarks["Runtime"] / pki_benchmarks["TestCases"] / 1000,
            "LOMAP": 0,
            "Improvement": 0,
            "Unit": "ms",
        },

        "Proof Size": {
            "NaivePKI": pki_benchmarks["Bandwidth"] / pki_benchmarks["TestCases"] / 1024,
            "LOMAP": 0,
            "Improvement": 0,
            "Unit": "KB"
        },

        "Memory Consumption": {
            "NaivePKI": pki_benchmarks["Memory"] / pki_benchmarks["TestCases"] / 1024,
            "LOMAP": 0,
            "Improvement": 0,
            "Unit": "bytes"
        },

        "Permanent Storage": {
            "NaivePKI": pki_benchmarks["Storage"] / pki_benchmarks["TestCases"],
            "LOMAP": 0,
            "Improvement": 0,
            "Unit": "KB"
        }
    }

    with open(f"{pwd}/results/metrics.json", "w") as file:
        dump(metrics, file)

    clean_test_environment()
