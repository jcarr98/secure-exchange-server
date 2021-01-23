"""All cryptography methods used by the server"""

# Python imports
import os
import hashlib, binascii

# Crypto imports
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Database variable
__DATABASE = "%s/database" % os.getcwd()

# RSA
def generate_rsa():
    """Generates and saves RSA key

        Returns:
            True if successful, False if unsuccessful
    """
    # Generate key
    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            backend=default_backend(),
            key_size=2048,
        )
    except:
        print("Issue generating rsa key")
        return False

    # Save private key
    try:
        with open("%s/%s" % (os.getcwd(), "serverprivate.pem"), "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.close()
    except:
        print("Error saving private key")
        return False

    # Save public key
    try:
        with open("%s/%s" % (os.getcwd(), "serverpublic.pem"), "wb") as f:
            # Get public key
            public = key.public_key()

            # Save bytes
            f.write(public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            f.close()
    except:
        print("Error saving public key")
        return False

    return True

def encrypt_rsa(msg, key):
    """Encrypt message with RSA
            
            Parameters:
                msg (str): The message to encrypt
                key (RSAPublicKey): The RSA key to encrypt with
            
            Returns:
                Encrypted message
    """
    # Convert message to bytes
    if type(msg) is not bytes:
        msg = msg.encode('utf-8')

    # Encrypt message
    enc = key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return enc

def decrypt_rsa(msg):
    """Decrypt message encrypted with RSA
            
            Parameters:
                msg (str): Encrypted message to decrypt

            Returns:
                Unencrypted message
    """
    # Get server's private key
    try:
        with open("%s/%s" % (os.getcwd(), "serverprivate.pem"), "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except FileNotFoundError:
        print("Private key file not found")
        return None

    dec = key.decrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    return dec.decode('utf-8')


def get_server_public_key():
    """Get server's public key

            Return:
                An RSA public key
    """
    # Read key from file
    try:
        with open("%s/%s" % (os.getcwd(), "serverpublic.pem"), "rb") as f:
            key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        print("Public key file not found")
        return None

    return key

def get_server_private_key():
    """Get server's private key

            Returns:
                An RSA private key
    """
    # Read key from file
    try:
        with open("%s/%s" % (os.getcwd(), "serverprivate.pem"), "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except FileNotFoundError:
        print("Private key not found")
        return None

    return key

def get_user_public_key(user):
    """Gets the public key of the specified user
    
            Parameter:
                user (str): User who's public key to get

            Returns:
                Public RSA key of user
    """
    # Read key from file
    try:
        with open("%s/users/%s/publicKey.pem" % (__DATABASE, user), "rb") as f:
            key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        print("Public key not found")
        return None

    return key

# Fernet
def generate_fernet():
    """Generate a Fernet key

            Returns:
                A Fernet key
    """
    return Fernet.generate_key()

def encrypt_fernet(msg, key):
    """Encrypts message with Fernet

            Parameters:
                msg (str): Message to encrypt
                key (Fernet): Key to encrypt message with
    """
    # Create Fernet object
    encryptor = Fernet(key)

    # Encrypt message
    enc = encryptor.encrypt(msg)

    # Return encrypted message
    return enc

def decrypt_fernet(msg, key):
    """Decrypts message encrypted with Fernet

            Parameters:
                msg (str): The encrypted message to encrypt
                key (Fernet): Key to use to decrypt message
            
            Returns:
                Unencrypted message
    """
    # Create Fernet object
    decryptor = Fernet(key)

    # Decrypt message
    dec = decryptor.decrypt(msg)

    # Return decrypted message
    return dec


def get_user_session_key(user):
    """Gets the Fernet key stored for the user

            Parameter:
                user (str): User who's session key to get

            Returns:
                Fernet key of user's session
    """
    try:
        with open("%s/users/%s/keys" % (__DATABASE, user), "rb") as f:
            key = f.read()
    except FileNotFoundError:
        print("User session key not found")
        return None

    return key

# Other
def hash_password(pwd, salt=None):
    """Hash the given password. If a salt is provided, use that salt"""

    if salt is None:
        # Generate salt
        uSalt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    else:
        uSalt=salt.encode('utf-8')

    safePwd = hashlib.pbkdf2_hmac(
        'sha256',
        pwd.encode('utf-8'),
        uSalt,
        100000
    )

    safePwd = binascii.hexlify(safePwd)

    return safePwd.decode('ascii'), uSalt.decode('ascii')