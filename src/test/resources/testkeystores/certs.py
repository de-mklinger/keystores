#!/usr/bin/python3

import os
import subprocess
import tempfile
import datetime

def main():
    ca_cert_file, ca_key_file, ca_pkcs12_cert_file = generate_ca("testca", days=3650)
    generate_server("test-server", ca_cert_file, ca_key_file, days=3650)

def generate_ca(cn, days=90):
    key = genrsa_pkcs8()
    key_file = "ca-key.pem"
    write_to_file(key_file, key)

    csr = generate_csr(key_file, cn, o="mklinger GmbH")
    
    cert = generate_ca_cert(csr, key_file, days)
    cert_file = "ca-cert.pem"
    write_to_file(cert_file, cert)

    pkcs12_cert = to_pkcs12(key_file, cert_file)
    pkcs12_cert_file = "ca-cert.p12".format(cn)
    write_to_file(pkcs12_cert_file, pkcs12_cert)

    return (cert_file, key_file, pkcs12_cert_file)

def generate_server(cn, ca_cert_file, ca_key_file, days=90):
    key = genrsa_pkcs8()
    key_file = "server-key.pem"
    write_to_file(key_file, key)
        
    csr = generate_csr(key_file, cn, o="test-server")
    
    cert = generate_cert(csr, ca_cert_file, ca_key_file,
                clientAuth=False,
                serverAuth=True,
                dnsSans = [ "localhost" ], 
                ipSans = [ "127.0.0.1" ],
                days = days)
    
    cert_file = "server-cert.pem"
    write_to_file(cert_file, cert)

    ca_chain = to_string(cert) + "" + read_from_file(ca_cert_file)
    ca_chain_file = write_to_tempfile(ca_chain)

    pkcs12 = to_pkcs12(key_file, cert_file, ca_chain_file=ca_chain_file)
    pkcs12_file = "server.p12".format(cn)
    write_to_file(pkcs12_file, pkcs12)

    return (cert_file, key_file, pkcs12)

def generate_client(cn, ca_cert_file, ca_key_file, days=90):
    key = genrsa_pkcs8()
    key_file = "client-key.pem".format(cn)
    write_to_file(key_file, key)
    
    csr = generate_csr(key_file, cn, o="test-client")
    
    cert = generate_cert(csr, ca_cert_file, ca_key_file,
                clientAuth=True,
                serverAuth=False,
                days = days)
    
    cert_file = "client-cert.pem".format(cn)
    write_to_file(cert_file, cert)

    ca_chain = to_string(cert) + "" + read_from_file(ca_cert_file)
    ca_chain_file = write_to_tempfile(ca_chain)

    pkcs12 = to_pkcs12(key_file, cert_file, ca_chain_file=ca_chain_file)
    pkcs12_file = "client.p12".format(cn)
    write_to_file(pkcs12_file, pkcs12)

    return (cert_file, key_file, pkcs12)


def generate_csr(key_file, cn, o=None):
    config = \
        "[req]\n" \
        "prompt = no\n" \
        "distinguished_name = dn\n" \
        "[dn]\n" \
        "CN=" + cn + "\n"
        
    if not o is None:
        config += \
            "O=" + o + "\n"
            
    config_file = write_to_tempfile(config)
    
    return run_for_stdout([
        'openssl', 'req',
        '-new',
        '-sha256',
        '-key', key_file,
        '-config', config_file
    ])

def generate_ca_cert(csr, sign_key_file, days=90):
    ext= \
        "subjectKeyIdentifier = hash\n" \
        "authorityKeyIdentifier = keyid\n" \
        "basicConstraints = CA:true\n"
    ext_file = write_to_tempfile(ext)

    return run_for_stdout([
        'openssl', 'x509',
        '-req',
        '-sha256',
        '-extfile', ext_file,
        '-signkey', sign_key_file, 
        '-set_serial', to_string(get_serial()),
        '-days', to_string(days)
    ], input=csr)

def generate_cert(csr, ca_cert_file, ca_key_file, days=90, clientAuth=False, serverAuth=False, dnsSans=[], ipSans=[]):
    ext= \
        "subjectKeyIdentifier = hash\n" \
        "authorityKeyIdentifier = keyid, issuer\n" \
        "basicConstraints = CA:false\n"
    
    if clientAuth or serverAuth:
        extendedKeyUsageParts = []
        if serverAuth:
            extendedKeyUsageParts.append("serverAuth")
        if clientAuth:
            extendedKeyUsageParts.append("clientAuth")
        extendedKeyUsage = ", ".join(extendedKeyUsageParts)
        ext = ext + \
            "extendedKeyUsage = " + extendedKeyUsage + "\n"

    if len(ipSans) > 0 or len(dnsSans) > 0:
        subjectAltNameParts = []
        for dnsSan in dnsSans:
            subjectAltNameParts.append("DNS:" + dnsSan)
        for ipSan in ipSans:
            subjectAltNameParts.append("IP:" + ipSan)
        subjectAltName = ", ".join(subjectAltNameParts)
        ext = ext + \
            "subjectAltName = \"" + subjectAltName + "\"\n"

    ext_file = write_to_tempfile(ext)

    return run_for_stdout([
        'openssl', 'x509',
        '-req',
        '-sha256',
        '-extfile', ext_file,
        '-CA', ca_cert_file,
        '-CAkey', ca_key_file, 
        '-set_serial', to_string(get_serial()),
        '-days', to_string(days)
    ], input=csr)

def to_pkcs12(key_file, cert_file, ca_chain_file=None):
    command = [
        'openssl', 'pkcs12', '-export',
        '-inkey', key_file,
        '-in', cert_file,
        '-passout', 'pass:'
    ]
    
    if not ca_chain_file is None:
        command.extend([
            '-certfile', ca_chain_file
        ])
        
    return run_for_stdout(command)

serial=0
def get_serial():
    global serial
    serial += 1
    return serial

def write_to_tempfile(data):
    (fd, path) = tempfile.mkstemp()
    os.close(fd)
    write_to_file(path, data)
    return path

def write_to_file(path, data):
    with open(path, "wb") as out:
        out.write(to_bytes(data))

def read_from_file(path):
    with open(path, "r") as out:
        return out.read()

def to_string(x):
    arg_is_string = isinstance(x, str)
    if isinstance(x, str):
        return x
    elif isinstance(x, bytes):
        return x.decode("UTF-8")
    else:
        return "{}".format(x)

def to_bytes(x):
    arg_is_string = isinstance(x, str)
    if isinstance(x, str):
        return x.encode("UTF-8")
    elif isinstance(x, bytes):
        return x
    else:
        return "{}".format(x).encode("UTF-8")

def run_for_stdout(command, input=None):
    result = subprocess.run(command, stdout=subprocess.PIPE, input=input, check=True)
    return result.stdout

def genrsa_pkcs8():
    return to_pkcs8_if_needed(genrsa())

def genrsa():
    return run_for_stdout([
        'openssl', 
        'genrsa', 
        '2048'])

def to_pkcs8_if_needed(key):
    arg_is_string = isinstance(key, str)
    if arg_is_string:
        key_str = key
        key_b = key.encode("ASCII")
    else:
        key_str = key.decode("ASCII")
        key_b = key
    
    if key_str.startswith("-----BEGIN RSA PRIVATE KEY"):
        pkcs8_b = run_for_stdout([
            'openssl', 
            'pkcs8', 
            '-topk8', 
            '-inform', 'pem', 
            '-in', '/dev/stdin', 
            '-outform', 'pem', 
            '-nocrypt'], 
            input=key_b).strip()
        
        # When argument was bytes, return bytes
        if arg_is_string:
            return pkcs8_b.decode("ASCII")
        else:
            return pkcs8_b
        
    else:
        return key

def today():
    return "{:%Y%m%d}".format(datetime.date.today())
  
main()