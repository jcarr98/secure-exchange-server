from os.path import getctime
import socket
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def send_packet(user, pwd):
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 8008))

    msg = "<sequence number>,<acknowledgement number>,HELLO,SecureClient,<checksum>".encode('utf-8')
    sock.sendall(msg)

    data = sock.recv(1024).decode('utf-8')
    
    print(data)

    receivedKey = data.split(",")[4]

    key = clean_key(receivedKey)

    msg = ("<sequence number>,<acknowledgement number>,AUTH,%s,%s,<checksum>" % (user, pwd)).encode('utf-8')
    msgEnc = key.encrypt(
        msg,
        padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
    )
    
    sock.sendall(msgEnc)

    data = sock.recv(1024).decode('utf-8')

def clean_key(key):
    keyUpdated = False

    key = key.encode('utf-8')

    # Hash new key
    new = hashlib.sha256()
    new.update(key)

    # Hash old key
    existing = hashlib.sha256()
    
    try:
        with open("%s/serverInfo.pem" % os.getcwd(), "rb") as f:
            existingBytes = f.read()
            f.close()
        
        existing.update(existingBytes)

        keyUpdated = new.digest() != existing.digest()
    except FileNotFoundError:
        # No key found
        keyUpdated = True

    if keyUpdated:
        print("Updated key")
        # Save new key
        with open("%s/serverInfo.pem" % os.getcwd(), "wb") as f:
            f.write(key)
            f.close()
    else:
        print("Key not updated")

    # Load and return key
    with open("%s/serverInfo.pem" % os.getcwd(), "rb") as f:
        keyToReturn = serialization.load_pem_public_key(f.read())
        f.close()

    return keyToReturn
            


if __name__ == "__main__":
    while True:
        userInput = input("username/pass to send, q to quit\n")
        if userInput == "q":
            break
        else:
            data = userInput.split(" ")
            send_packet(data[0], data[1])