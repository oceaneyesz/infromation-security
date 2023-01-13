import socket
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM
from OpenSSL.crypto import dump_privatekey, dump_publickey

from OpenSSL import crypto, SSL

def cert_gen(
    emailAddress="CUHK@163.com",
    commonName="CUSIS",
    countryName="CN",
    localityName="newtown",
    stateOrProvinceName="hk",
    organizationName="cuhk",
    organizationUnitName="CUHK",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="selfsigned.crt"):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(validityStartInSeconds)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

def create_cert(caCert,deviceCsr,CAprivatekey):
    serial_no = 1
    notBeforeVal = 0
    notAfterVal = 10*365*24*60*60
    cert = crypto.X509()
    cert.set_serial_number(serial_no)
    cert.gmtime_adj_notBefore(notBeforeVal)
    cert.gmtime_adj_notAfter(notAfterVal)
    cert.set_issuer(caCert.get_subject())
    cert.set_subject(deviceCsr.get_subject())
    cert.set_pubkey(deviceCsr.get_pubkey())
    cert.sign(CAprivatekey, 'sha512')
    return cert

if __name__ == '__main__':
    ip_port = ('127.0.0.1', 8080)
    sk = socket.socket()
    sk.bind(ip_port)
    sk.listen(5)
    L_buffer = 10240
    S_buffer = 2048
    print("the CUHK is ready, waiting connection")
    print("the CUHK listens to SID1")
    conn, address = sk.accept()
    step = 0
    while step < 2:
        cert_gen()
        CertificateRequest = conn.recv(L_buffer).decode()
        print("student2/3 login in successfully")
        print("receive CSR")

        deviceCsr = crypto.load_certificate_request(FILETYPE_PEM, CertificateRequest)
        CA_privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, open("private.key", 'rb').read())
        caCert = crypto.load_certificate(crypto.FILETYPE_PEM,open("selfsigned.crt", 'rb').read())
        Stu_cert2 = create_cert(caCert,deviceCsr,CA_privatekey)
        print("create the cert2 successfully")

        conn.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM, Stu_cert2))
        client_data = conn.recv(1024).decode()
        if client_data == "exit":
            exit("exit.")
        print("the client %s sends the message %s" % (address, client_data))
        conn.sendall("receive message successufully".encode())
        conn.close()
        step += 2
