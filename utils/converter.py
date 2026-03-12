from cryptography.hazmat.backends import default_backend
from cryptography import x509
from hashlib import sha256

from os.path import isdir, abspath, isabs, join, exists
from os import listdir, mkdir

from concurrent.futures import ThreadPoolExecutor

import argparse

def get_all_certificates(trust_store_path: str, recursive: bool = False) -> list[str]:
    """Traverses the trust store for certificates.

    Retrieves all certificates in the trust store. If the recursive flag is enabled, it also
    retrieves certificates in subdirectories.

    Args:
        trust_store_path (str) : The path to the trust store. If the path is relative, it will be automatically
                        converted to absolute format.
        recursive (bool) : Denotes whether to retrieve certificates from subdirectories. Defaults to False.
    
    Returns:
        list[str] : A list containing the paths to all certificates found.
    """
    abs_path = trust_store_path if isabs(trust_store_path) else abspath(trust_store_path)
    formats = ('.pem', '.der', '.crt', '.cer')
    cert_list = []

    # Early exit in case of invalid paths
    if not isdir(abs_path):
        return cert_list

    for file in listdir(abs_path):
        if isdir(file) and recursive:
            cert_list.extend(get_all_certificates(join(abs_path, file), recursive))
        elif file.endswith(formats):
            cert_list.append(join(abs_path, file))

    return cert_list

def convert_certificate(cert_path: str, out_dir: str) -> bool:
    """Converts a X.509 certificate to LOMAP compressed form.

    The compressed certificate is stored in the provided output directory.
    The function fails if the directory is unaccessible or the certificate is not readable.

    Args:
        cert_path (str) : The path to the digital certificate.
        out_dir (str) : The path to the output directory for the LOMAP trust store.

    Returns:
        bool : Denotes whether the compressed certificate was successfully created.
    """
    certificate = None
    cert_name = cert_path[cert_path.rfind('/') + 1 : cert_path.rfind('.')]

    with open(cert_path, "rb") as file:
        if not file or not file.readable():
            return False

        certificate = x509.load_pem_x509_certificate(file.read(), default_backend())
    if not certificate:
        return False

    if not isdir(out_dir):
        return False

    with open(join(out_dir, cert_name + ".lomap"), "w") as file:
        if not file.writable():
            return False

        data = [
            sha256(str(certificate.serial_number).encode('utf-8')).hexdigest() + '\n',
            sha256(certificate.subject.rfc4514_string().encode('utf-8')).hexdigest() + '\n',
            str(certificate.not_valid_before_utc) + '\n',
            str(certificate.not_valid_after_utc) + '\n',
            sha256(str(certificate.public_key).encode('utf-8')).hexdigest() + '\n'
        ]

        file.writelines(data)   
        file.writelines([sha256(''.join(data).encode('utf-8')).hexdigest()])
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog = "LOMAP Converter",
        description = "Converts existing trust stores in their compressed format according to LOMAP specifications.",
        epilog = "")
    
    parser.add_argument('trust_store', help = "The path to the trust store directory.")
    parser.add_argument('-o', '--output_dir', help = "The path to the output directory. Defaults to `./results/`", default = "./results/", required = False)
    parser.add_argument('-t', '--threads', help = "Number of threads to use for conversion. Defaults to 1.", default = 1, required = False)
    parser.add_argument('-r', '--recursive', help = "Traverse subdirectories. Defaults to False.", default = False, required = False, action = 'store_true')

    args = parser.parse_args()

    cert_list = get_all_certificates(args.trust_store, args.recursive)
    
    if not exists(args.output_dir):
        mkdir(abspath(args.output_dir))

    with ThreadPoolExecutor(args.threads) as executor:
        results = []

        for cert_path in cert_list:
            results.append((cert_path, executor.submit(convert_certificate, cert_path, args.output_dir)))

        success_counter = len(results)
        for certificate, result in results:
            if not result.result():
                success_counter -= 1
                print(f"Conversion of certificate {certificate} failed.")
    print(f"Successfully converted {success_counter} certificates.")
