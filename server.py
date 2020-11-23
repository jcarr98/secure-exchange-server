import socket
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class SecureExchangeServer:
    def __init__(self):
        # Class variables
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 8008
        self._private = None
        self.public = None
        self.keyName = "serverRSA.pem"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        # Load key
        self.__load_key()

        # Start socket
        self.sock.bind((self.SERVER_IP, self.SERVER_PORT))
        self.sock.listen(10)
        self.__welcome()

    def __welcome(self):
        # Wait for connection
        print("Waiting for connection...")
        connection, client_addr = self.sock.accept()

        # Start talking
        self.__talk(connection, client_addr)

    def __talk(self, connection, client_addr):
        """Receive and read data sent by client

            Parameters:
                connection: The connection with client via tcp
                client_addr: information about client address
        """
        # Receive first message, should be '<sequence number>,<acknowledgement number>,HELLO,SecureClient,<checksum>'
        data = connection.recv(1024).decode('utf-8')
        print(data)
        
        # Verify checksum
        if not self.__verify_checksum(data):
            self.__err("Bad checksum", connection)
            return

        parsedData = data.split(",")
        if parsedData[2] != "HELLO":
            self.__err("Bad greeting", connection)
            return
    
        # Craft second packet, should be '<sequence number>,<acknowledgement number>,HELLO,SecureServer,<public key>,<checksum>'
        print("Sending public key")
        msg = "<sequence number>,<acknowledgement number>,HELLO,SecureServer,%s," % self.__getPublicKey()
        checksum = self.__generate_checksum(msg)
        msg = ("%s%s" % (msg, checksum)).encode('utf-8')

        # Send packet
        connection.sendall(msg)

        # Wait for second message to authenticate user, should be '<sequence number> <acknowledgement number> AUTH <username> <password> <checksum>'
        data = connection.recv(1024)
        # Decrypt data
        data = self._private.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        data = data.decode('utf-8')
        print(data)

        # Verify checksum
        if not self.__verify_checksum(data):
            self.__err("Bad checksum", connection)
            return

        # Parse data
        parsedData = data.split(",")

        # Find options
        if len(parsedData != 6):
            self.__err("No authentication message", connection)
            return
        if parsedData[2] == "AUTH":
            # Authenticate user
            user = parsedData[3]
            pwd = parsedData[4]
            if not self.__auth(user, pwd):
                # Create bad authentication packet
                msg = "0,0,BAD,"
                msg.encode('utf-8')
            else:
                # Generate session key
                key = Fernet.generate_key()

                # Save key to user
                with open("%s/database/users/%s/keys/session.key" % (os.getcwd(), user), "wb") as f:
                    f.write(f)
                    f.close()
                msg = "0,0,OK,<checksum>".encode('utf-8')

                # Encrypt message with user's public key
                

            # Send message
            checksum = self.__generate_checksum(msg)
            msg = ("%s%s" % (msg, checksum)).encode('utf-8')
            connection.sendall(msg)
        else:
            self.__err("Not implemented yet", connection)

        connection.close()
        self.__welcome()

    def __auth(self, username, password):
        # Get username from database
        try:
            with open("%s/database/users/%s/userInfo.json" % (os.getcwd(), username), "r") as f:
                userData = json.load(f)
                f.close()
        except FileNotFoundError:
            print("File not found: %s/database/users/%s/userInfo.json" % (os.getcwd(), username))
            return False

        # Compare passwords
        print(userData)
        return userData["password"] == password

    def __err(self, msg, connection):
        print(msg)
        connection.close()
        self.__welcome()

    def __load_key(self):
        files = os.listdir()
        # Check if key exists
        if self.keyName in files:
            # Load key
            print("Key found, loading...")
            with open("%s/%s" % (os.getcwd(), self.keyName), "rb") as f:
                self._private = serialization.load_pem_private_key(f.read(), password=None)
                self.public = self._private.public_key()
                f.close()

            print("Key loaded!")
        else:
            # Create key
            self._private = self.__create_key()
            self.public = self._private.public_key()
            print("No key found... generating new one")

    def __create_key(self):
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Save key
        with open("%s/%s" % (os.getcwd(), self.keyName), "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.close()

        return key

    def __getPublicKey(self):
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def __generate_checksum(self, packet):
        # Convert packet into bytes
        packet = packet.encode('utf-8')
        total = 0
        for i in range(0, len(packet)):
            total += packet[i]

        return format(total, '05d')

    def __verify_checksum(self, msg):
        # Separate message and checksum
        msg = msg.rsplit(",", 1)
        
        # Generate checksum
        newChecksum = self.__generate_checksum(msg[0])

        # Compare the checksums
        return newChecksum == msg[1]

    def __encrypt_message(self, msg):
        pass