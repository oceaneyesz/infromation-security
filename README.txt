You should use "python CUHK.py" "python Blackboard.py" to run the two servers.
The CUHK.py listens the 8080. The Blackboard.py listens the 80.
The Student.py will first connect with the CUHK.py with socket.
The ip is 127.0.0.1.
Because using s.sendall two consecutive times will cause some errors, we use "while" and "step" to control
the sending and receiving.The number of step shows the real step of the lab.
After the Student.py gets the Cert2, it will send "exit" to CUHK.py to close the socket.
The CUHK.py and Student.py would write the certificate to the file and save.
After that, Student.py would connect to the 80 to connect with the Blackboard.py.
The Student.py would send SID2 and Cert2 to Blackboard.py.
And the Blackboard would read the file of certificate of CUHK to check Cert2.
Blackboard uses the sha1 to generate the session.
The front 32bytes of public key of the Cert2 will be used as key. And sha1 would be used as session.
And the blackboard would send the session to the student and student uses cert2 to decrypt. 
I use Crypto.Cipher and some trick to make it confirm to the AES.In fact, the Crypto has the fuction about it.
I use AES-CBC as MAC to vertify.
The details of the messages have been printed.
In step 6, Using key from the blackboard as the key of GCM_mode.
I think the certificate should be saved in file just like the real server. 
So I create file to save them. And Blackboard.py could read the file of root certifacate.
Some details about this lab have some ambiguous processes. I deal with refering to the offical document and
the stackoverflow.
To make it simplify, I use the default studentId, you do not need to input them.
In fact, I have writed the code to input studentID to login in. But it seems that it is very strange 
in the last steps. So I delete the code about it.
