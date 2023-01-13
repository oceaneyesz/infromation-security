import socket
import re
import time
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM
from OpenSSL.crypto import dump_privatekey, dump_publickey
from hashlib import md5
from OpenSSL import crypto, SSL
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha1
import base64
import random

_PEM_RE = re.compile(b'-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?\n?', re.DOTALL)

def parse_chain(chain):
    # returns a list of certificates
    return [c.group() for c in _PEM_RE.finditer(chain)]

def encrypt_CBC(data, password):
    bs = AES.block_size
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    iv = Random.new().read(bs)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    data = cipher.encrypt(pad(data).encode("utf-8"))
    data = iv + data
    return (data)


if __name__ == '__main__':
    ip_port = ('127.0.0.2', 80)
    sk = socket.socket()
    sk.bind(ip_port)
    sk.listen(5)
    L_buffer = 10240
    S_buffer = 2048
    print("the Blackboard is ready, waiting connection")
    print("the blackboard listens to SID1")
    conn, address = sk.accept()
    step = 3

    while step <= 6:
        if step == 3:
            student_cert = conn.recv(L_buffer).decode()
            SID2 = student_cert[:10]
            student_cert = student_cert[10:]
            store = crypto.X509Store()
            for cert in parse_chain(open('selfsigned.crt').read().encode()):
                store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
            stu2_cert = crypto.load_certificate(crypto.FILETYPE_PEM, student_cert)
            ctx = crypto.X509StoreContext(store, stu2_cert)
            res = ctx.verify_certificate()
            if res == None:
                print("verify certificate seccessfully")

            session = sha1(str(time.time()).encode('utf-8'))  # generate session
            session = session.hexdigest()
            time.sleep(0.1*random.random())
            # key = md5(str(time.time()).encode('utf-8'))  # generate random key
            # print(len(key))
            # key = key.hexdigest()
            key = dump_publickey(FILETYPE_PEM,stu2_cert.get_pubkey())[27:59]
            # print(key)
            # key = key.hexdigest()
            encrypt_session = encrypt_CBC(session, key)
            conn.sendall(encrypt_session)
            step = 4
            

        if step == 4:
            cipher = AES.new(session[:32].encode(), AES.MODE_GCM, key)
            cipher.update(b'header')
            ciphertext = conn.recv(L_buffer)
            plaintext = cipher.decrypt(ciphertext).decode()
            step = 6

        if step == 6:
            mac_tag = conn.recv(S_buffer)
            try:
                cipher.verify(mac_tag)                               
            except:
                print("MAC Authentication failed")
                step += 1
                break
            else:
                print("MAC Authentication is successful")
            # client_data = conn.recv(2048).decode()
            # if client_data == "exit":
            #     exit("exit.")
            # else:
            #     print(client_data)
            # print("the client %s sends the message %s" % (address, client_data))
            print(plaintext)
            conn.sendall("receive message successufully".encode())
            step += 1

    conn.close()
