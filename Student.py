import socket
import time
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM
from OpenSSL.crypto import dump_privatekey, dump_publickey
from Crypto.Cipher import AES
from Crypto import Random
from OpenSSL import crypto, SSL
import base64

def decrypt_cbc(data, password):
    bs = AES.block_size
    if len(data) <= bs:
        return (data)
    iv = data[:bs]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    data  = cipher.decrypt(data[bs:])
    data = data.decode()[:40]
    return (data)

def generate_CSR(pk,studentID):
    csrrequest = crypto.X509Req()
    csrrequest.get_subject().C  = "CN"
    csrrequest.get_subject().O  = "CUSIS"
    csrrequest.get_subject().CN = studentID
    csrrequest.set_pubkey(pk)
    csrrequest.sign(pk,"sha256")
    return csrrequest
    
if __name__ == '__main__':
    ip_port = ('127.0.0.1', 8080)
    s = socket.socket()
    s.connect(ip_port)
    step = 1
    L_buffer = 10240
    S_buffer = 2048
    data_message = "This is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\nThis is submission from SID1/2/3.\n"

    while step==1:
        # error = 1
        # while error == 1:
        #     studentID=input("Please input your Student ID(SID1 SID2 SID3):")
        #     if studentID=='SID1': 
        #         req_back=generate_CSR(pk1,studentID)
        #         print("student1 try to login")
        #         error = 0
        #     elif studentID=='SID2':
        #         req_back=generate_CSR(pk2,studentID)
        #         print("student2 try to login")
        #         error = 0
        #     elif studentID=='SID3':
        #         req_back=generate_CSR(pk3,studentID)
        #         print("student3 try to login")
        #         error = 0
        #     else :
        #         print("Please type the right SID")
        SID1 = "1155123456"
        SID2 = "1155123457"
        SID3 = "1155123458"
        print('SID1:%s,SID2:%s,SID3:%s'%(SID1,SID2,SID3))
        
        pk = PKey() 
        pk.generate_key(TYPE_RSA,2048)
        dpub = dump_publickey(FILETYPE_PEM, pk)
        dpri = dump_privatekey(FILETYPE_PEM, pk)

        # send CSR request
        csrrequest = generate_CSR(pk,SID2)
        s.sendall(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csrrequest))
        print("SID2 send CSR request successfully")

        #This is step 2
        server_reply = s.recv(L_buffer).decode()
        Cert2 = server_reply
        CERT_FILE = "stu_cert2.crt"
        with open(CERT_FILE, "wt") as f:
            f.write(server_reply)
        print("SID2 sign finished")

        if server_reply != "":
            message = "exit"
            s.sendall(message.encode())
            s.close()
            step += 1


    #The student has finished the connection with the blackboard
    # The student try to connect with the blackboard
    step = 3
    s.close()
    print("request to blackboard")
    ip_port = ('127.0.0.2', 80)
    s = socket.socket()
    s.connect(ip_port)

    while step <= 6:
        if step == 3:
            print("SID2 send request to blackboard")
            s.sendall(SID2.encode()+Cert2.encode())
            encrypt_data = s.recv(L_buffer)
            step = 5
        if step == 5:
            print("student1 receive the session key")
            stu2_cert = crypto.load_certificate(crypto.FILETYPE_PEM, Cert2)
            key = dump_publickey(FILETYPE_PEM,stu2_cert.get_pubkey())[27:59]
            # print(key)
            decrypt_session = decrypt_cbc(encrypt_data,key)
            print("student3 send the message")
            cipher = AES.new(decrypt_session[:32].encode(), AES.MODE_GCM, key)
            cipher.update(b'header')
            ciphertext = cipher.encrypt(data_message.encode())
            s.sendall(ciphertext)
            step = 6
        if step == 6:
            mac_tag = cipher.digest()
            s.sendall(mac_tag)
            print("student3 send MAC")
            step += 1
        # s.sendall(str(SID2).encode())

