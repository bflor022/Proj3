from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

"""
This file keeps all cryptographic logic in one place:
key generation, key import/export, encryption, decryption, and hashing.
Separating this from the socket code makes the client and server easier to read.
"""

"""
generate_keys()

Purpose:
    Creates a new RSA public/private key pair for one side of the connection.

Why Needed:
    RSA requires two linked keys:
    - private key: kept secret and used to decrypt incoming ciphertext
    - public key: shared with the other side and used to encrypt outgoing data

Returns:
    A tuple containing:
    - private RSA key object
    - matching public RSA key object

Design Choice:
    2048-bit RSA is used because it is a common secure key size and is
    appropriate for this project.
"""
def generate_keys():

    """
    Each side creates its own RSA keypair at startup.
    The private key stays secret, while the public key is shared with the other side.
    """
    
    # Generate a brand-new 2048-bit RSA keypair and return BOTH:
    private_key = RSA.generate(2048)
    # 1. the private key object
    # 2. the matching public key object

    # - Use RSA.generate(2048)
    # - The public key is derived from the private key object
    public_key = private_key.publickey()
    return private_key, public_key
    
    raise NotImplementedError("TODO: implement generate_keys")


"""
export_public_key(public_key)

Purpose:
    Converts an RSA public key object into bytes so it can be sent across a socket.

Why Needed:
    Sockets transmit bytes, not Python key objects. The public key must be
    serialized before the client or server can send it to the other side.

Parameters:
    public_key - RSA public key object

Returns:
    Byte representation of the public key, typically PEM formatted
"""
def export_public_key(public_key):
    # Convert the RSA public key object into bytes for transmission/storage
    return public_key.export_key()


"""
import_public_key(key_bytes)

Purpose:
    Reconstructs an RSA public key object from received bytes.

Why Needed:
    After the other side sends its public key over the socket, those bytes need
    to be converted back into a usable RSA key object before encryption can occur.

Parameters:
    key_bytes - Byte representation of a public key

Returns:
    RSA public key object
"""
def import_public_key(key_bytes):
    # Parse the received key bytes and rebuild the RSA public key object
    return RSA.import_key(key_bytes)


"""
encrypt_message(message, public_key)

Purpose:
    Encrypts a plaintext string using the recipient's RSA public key.

Why Needed:
    The client encrypts the message using the server's public key so only the
    server can decrypt it with its private key. The server encrypts the hash
    using the client's public key so only the client can decrypt it.

Parameters:
    message    - Plaintext string to encrypt
    public_key - RSA public key object of the recipient

Returns:
    Ciphertext bytes

Implementation Notes:
    PKCS1_OAEP is used as the RSA padding scheme because it is a modern,
    safer choice than raw RSA encryption.
"""
def encrypt_message(message, public_key):
    # TODO:
    # Encrypt the plaintext message using the recipient's RSA public key.
    cipher = PKCS1_OAEP.new(public_key)

    return cipher.encrypt(message.encode())
    # What this function must do:
    # 1. Build an OAEP cipher object from the provided public key
    # 2. Convert the plaintext string into bytes using .encode()
    # 3. Encrypt the bytes and return the ciphertext bytes
    #
    # Hints:
    # - Use PKCS1_OAEP.new(public_key)
    # - Return cipher.encrypt(...)
    raise NotImplementedError("TODO: implement encrypt_message")


"""
decrypt_message(ciphertext, private_key)

Purpose:
    Decrypts ciphertext bytes using the matching RSA private key.

Why Needed:
    Only the holder of the private key should be able to recover the original
    plaintext that was encrypted with the corresponding public key.

Parameters:
    ciphertext  - Encrypted bytes
    private_key - RSA private key object belonging to the receiver

Returns:
    Decrypted plaintext string
"""
def decrypt_message(ciphertext, private_key):
    # Create an RSA cipher object using the private key and OAEP padding
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the ciphertext bytes and convert the result back to a string
    return cipher.decrypt(ciphertext).decode()


"""
compute_sha256(message)

Purpose:
    Computes the SHA-256 hash of a plaintext string.

Why Needed:
    SHA-256 provides an integrity check. If the message changes, even slightly,
    the resulting hash will be completely different. This allows the client to
    compare its locally computed hash against the server's returned hash.

Parameters:
    message - Plaintext string to hash

Returns:
    64-character hexadecimal SHA-256 digest string

Implementation Notes:
    - The input string must first be converted to bytes.
    - hexdigest() returns a printable hexadecimal representation of the hash.
"""
def compute_sha256(message):
    # TODO:
    # Compute the SHA-256 digest of the input message and return it as a hex string.
    #
    # What this function must do:
    # 1. Convert the plaintext string into bytes using .encode()
    # 2. Hash those bytes with hashlib.sha256(...)
    # 3. Return the printable hex digest with .hexdigest()
    
    # SHA-256 produces a fixed-length fingerprint of the message.
    # Even a small change in the plaintext creates a very different hash.
    
    return hashlib.sha256(message.encode()).hexdigest()
    
    raise NotImplementedError("TODO: implement compute_sha256")
