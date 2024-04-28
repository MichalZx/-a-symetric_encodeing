from typing import Union
from fastapi import Request, Form
import jinja2
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import binascii
from cryptography.fernet import Fernet
import secrets
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

# Global variable to store symmetric key
symmetric_key = None
# Global variables to store asymmetric keys
public_key = None
private_key = None


@app.get("/symmetric/key", tags=["symmetric"])
def generate_symmetric_key():
    """
       Generates a random symmetric key.

       Returns:
           dict: A dictionary containing the generated symmetric key.
    """
    global symmetric_key
    symmetric_key = Fernet.generate_key()
    return {"key": symmetric_key.hex()}

@app.post("/symmetric/key", tags=["symmetric"])
async def set_symmetric_key(key: str = Form(...)):
    """
    Sets the symmetric key.

    Args:
        key (str): The symmetric key provided as a hexadecimal string.

    Returns:
        dict: A message indicating the success of setting the symmetric key.
    """
    global symmetric_key
    symmetric_key = bytes.fromhex(key)
    return {"message": "Symmetric key set successfully"}


@app.post("/symmetric/encode", tags=["symmetric"])
def encode_message(message: str):
    """
    Encrypts a message using the symmetric key.

    Args:
        message (str): The message to be encrypted.

    Returns:
        dict: A dictionary containing the encrypted message.
    """
    global symmetric_key
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    encrypted_message = cipher.encrypt(message.encode())
    return {"encrypted_message": encrypted_message.hex()}


@app.post("/symmetric/decode", tags=["symmetric"])
def decode_message(encrypted_message: str):
    """
    Decrypts an encrypted message using the symmetric key.

    Args:
        encrypted_message (str): The encrypted message in hexadecimal string format.

    Returns:
        dict: A dictionary containing the decrypted message.
    """
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    try:
        decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message)).decode()
        return {"decrypted_message": decrypted_message}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed")



#asymetric
def set_keys(public_hex, private_hex):
    """
    Sets the public and private keys for asymmetric encryption.

    Args:
        public_hex (str): The public key provided as a hexadecimal string.
        private_hex (str): The private key provided as a hexadecimal string.
    """
    global public_key, private_key
    try:
        public_bytes = binascii.unhexlify(public_hex)
        private_bytes = binascii.unhexlify(private_hex)
        public_key = serialization.load_der_public_key(public_bytes)
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid key format")


@app.get("/asymmetric/key", tags=["asymmetric"])
def generate_asymmetric_key():
    """
    Generates a new RSA key pair.

    Returns:
        dict: A dictionary containing the generated public and private keys.
    """
    global public_key, private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    private_hex = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    return {"public_key": public_hex, "private_key": private_hex}


@app.get("/asymmetric/key/ssh", tags=["asymmetric"])
def get_ssh_key():
    """
    Retrieves the public and private keys in SSH format.

    Returns:
        dict: A dictionary containing the public and private keys in SSH format.
    """
    global public_key, private_key
    if public_key is None or private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric keys not generated")
    ssh_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    ssh_private_key = private_pem.decode()
    return {"public_key_ssh": ssh_public_key,"private_key_ssh": ssh_private_key }


@app.post("/asymmetric/key", tags=["asymmetric"])
async def set_key(keys: dict):
    """
    Sets the public and private keys for asymmetric encryption.

    Args:
        keys (dict): A dictionary containing the public and private keys as hexadecimal strings.

    Returns:
        dict: A message indicating the success of setting the keys.
    """
    global public_key, private_key
    public_hex = keys.get("public_key")
    private_hex = keys.get("private_key")
    if not public_hex or not private_hex:
        raise HTTPException(status_code=400, detail="Both public_key and private_key are required")
    set_keys(public_hex, private_hex)
    return {"message": "Keys set successfully"}


@app.post("/asymmetric/sign", tags=["asymmetric"])
async def sign_message_endpoint(message: str):
    """
    Signs a message using the private key.

    Args:
        message (str): The message to be signed.

    Returns:
        dict: A dictionary containing the signature of the message.
    """
    global private_key
    if not private_key:
        raise HTTPException(status_code=400, detail="Private key is not set")
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature = binascii.hexlify(signature).decode()
    return {"signature": signature}


@app.post("/asymmetric/verify", tags=["asymmetric"])
async def verify_message_endpoint(message: str, signature: str):
    """
    Verifies the signature of a message using the public key.

    Args:
        message (str): The message whose signature needs to be verified.
        signature (str): The signature of the message to be verified.

    Returns:
        dict: A dictionary indicating whether the signature is valid.
    """
    global public_key
    if not public_key:
        raise HTTPException(status_code=400, detail="Public key is not set")
    try:
        signature_bytes = binascii.unhexlify(signature)
        public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        is_valid = True
    except InvalidSignature:
        is_valid = False
    return {"is_valid": is_valid}

@app.post("/asymmetric/encode", tags=["asymmetric"])
async def encode_message(message: str):
    """
    Encrypts a message using the public key.

    Args:
        message (str): The message to be encrypted.

    Returns:
        dict: A dictionary containing the encrypted message.
    """
    global public_key
    if not public_key:
        raise HTTPException(status_code=400, detail="Public key is not set")
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ciphertext = binascii.hexlify(ciphertext).decode()
    return {"ciphertext": ciphertext}

@app.post("/asymmetric/decode", tags=["asymmetric"])
async def decode_message(ciphertext: str):
    """
    Decrypts an encrypted message using the private key.

    Args:
        ciphertext (str): The encrypted message to be decrypted.

    Returns:
        dict: A dictionary containing the decrypted message.
    """
    global private_key
    if not private_key:
        raise HTTPException(status_code=400, detail="Private key is not set")
    plaintext = private_key.decrypt(
        binascii.unhexlify(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    plaintext = plaintext.decode()
    return {"plaintext": plaintext}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)