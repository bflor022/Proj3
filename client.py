import socket
import sys
from crypto import *

HOST = '127.0.0.1'
PORT = 8080
MESSAGE = "Hello"

"""
The client follows the required project sequence:
connect -> receive data port -> tunnel public keys -> post encrypted message
-> receive encrypted hash -> compare hashes -> print Secure/Compromised
"""

"""
send_with_length(sock, data)

Purpose:
    Sends a complete message over TCP using a length prefix.

Why Needed:
    Prevents mixing of commands and binary data.

All commands and encrypted payloads are sent with a length prefix
# so the receiver can separate complete messages from the TCP byte stream.
"""
def send_with_length(sock, data):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)


"""
recv_exact(sock, n)

Purpose:
    Receives exactly n bytes from the socket.
"""
def recv_exact(sock, n):
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            raise ConnectionError("Socket connection closed unexpectedly")
        buffer += chunk
    return buffer


"""
recv_with_length(sock)

Purpose:
    Receives a full length-prefixed message.
"""
def recv_with_length(sock):
    # First 4 bytes = length
    length_data = recv_exact(sock, 4)

    # Convert to integer
    length = int.from_bytes(length_data, 'big')

    # Read full message
    return recv_exact(sock, length)


"""
main()

Purpose:
    Full client workflow:
    - Connect
    - Exchange keys
    - Send encrypted message
    - Verify integrity
"""
def main():
    print("Starting client...")

    """
    This optional command-line flag lets us simulate a bad response.
    It is useful for demonstrating the "Compromised" output case.
    """
    
    # Optional tamper flag
    tamper = len(sys.argv) > 1 and sys.argv[1].lower() == "tamper"

    print("Creating RSA keypair")

    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Convert public key to bytes
    public_key_bytes = export_public_key(public_key)

    print("RSA keypair created")

    print("Creating client socket")
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to server")
    control_sock.connect((HOST, PORT))

    """
    The client starts on the server's fixed control port and sends "connect"
    to request the temporary port that will be used for the data connection.
    """
    
    # Request data port
    send_with_length(control_sock, b"connect")

    # Receive assigned port
    data_port = int(recv_with_length(control_sock).decode())

    """
    Once the temporary data port is received, the control socket is no longer needed.
    All remaining communication happens on the data socket.
    """
    
    # Close control socket
    control_sock.close()

    print("Creating data socket")
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """
    The client now switches to the server's temporary data port
    for the tunnel and post commands.
    """
    
    # Connect to data port
    data_sock.connect((HOST, data_port))

    print("Requesting tunnel")

    """
    "tunnel" begins the public-key exchange phase.
    After this step, the client will know the server's public key.
    """
    
    # Start key exchange
    send_with_length(data_sock, b"tunnel")

    """
    The client sends its public key so the server can later encrypt
    the returned hash in a way that only this client can decrypt.
    """
    
    # Send client public key
    send_with_length(data_sock, public_key_bytes)

    # Receive server public key
    server_pub_bytes = recv_with_length(data_sock)

    """
    The server's public key arrives as bytes, so it must be reconstructed
    into an RSA key object before it can be used for encryption.
    """
    
    # Convert to RSA key
    server_public_key = import_public_key(server_pub_bytes)

    print("Server public key received")
    print("Tunnel established")

    print("Encrypting message:", MESSAGE)

    """
    The plaintext is encrypted with the server's public key.
    Only the server's private key can decrypt this ciphertext.
    """
    
    # Encrypt message using server public key
    encrypted_msg = encrypt_message(MESSAGE, server_public_key)

    print("Sending encrypted message:", encrypted_msg)

    """
    The post command tells the server that the next payload
    will be the encrypted application message.
    """
    
    # Send post command
    send_with_length(data_sock, b"post")

    # Send encrypted message
    send_with_length(data_sock, encrypted_msg)

    # Receive encrypted hash
    encrypted_hash = recv_with_length(data_sock)

    print("Received hash")

    """
    The returned hash was encrypted with the client's public key on the server side,
    so this client must use its private key to decrypt it.
    """
    
    # Decrypt hash
    server_hash = decrypt_message(encrypted_hash, private_key)

    """
    In tamper mode, the decrypted hash is deliberately changed
    so the final comparison fails and prints "Compromised."
    """
    
    # Optional tamper simulation
    if tamper:
        server_hash = server_hash[:-1] + ("0" if server_hash[-1] != "0" else "1")

    print("Computing hash")

    """
    The client hashes its original plaintext message locally
    so it can compare that value to the server's returned hash.
    """
    
    # Compute local hash
    local_hash = compute_sha256(MESSAGE)

    """
    Matching hashes mean the message integrity check passed.
    Different hashes mean the message or response may have been altered.
    """
    
    # Compare results
    if server_hash == local_hash:
        print("Secure")
    else:
        print("Compromised")

    data_sock.close()


if __name__ == "__main__":
    main()
