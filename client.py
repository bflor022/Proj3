import socket
import sys
from crypto import *

HOST = '127.0.0.1'
PORT = 8080
MESSAGE = "Hello"


"""
send_with_length(sock, data)

Purpose:
    Sends a complete message over TCP using a length prefix.

Why Needed:
    Prevents mixing of commands and binary data.
"""
def send_with_length(sock, data):
    # TODO:
    # Implement length-prefixed sending.
    #
    # What this function must do:
    # 1. Compute the length of the byte payload in 'data'
    # 2. Convert that integer length into exactly 4 bytes using big-endian format
    # 3. Send the 4-byte header followed by the payload bytes
    #
    # Hints:
    # - data is already bytes
    # - use len(data).to_bytes(4, 'big')
    # - use sock.sendall(...) so the full payload is sent
    #
    # Expected wire format:
    # [4-byte length][payload bytes]
    raise NotImplementedError("TODO: implement send_with_length")


"""
recv_exact(sock, n)

Purpose:
    Receives exactly n bytes from the socket.
"""
def recv_exact(sock, n):
    # TODO:
    # Implement a loop that keeps reading from the socket until exactly n bytes
    # have been received.
    #
    # What this function must do:
    # 1. Start with an empty bytes buffer
    # 2. While the buffer length is less than n:
    #    - call sock.recv(n - len(buffer))
    #    - append the received bytes to the buffer
    # 3. If recv() returns b'' before all bytes arrive, raise:
    #      ConnectionError("Socket connection closed unexpectedly")
    # 4. Return the completed buffer
    raise NotImplementedError("TODO: implement recv_exact")


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

    # Request data port
    send_with_length(control_sock, b"connect")

    # Receive assigned port
    data_port = int(recv_with_length(control_sock).decode())

    # Close control socket
    control_sock.close()

    print("Creating data socket")
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to data port
    data_sock.connect((HOST, data_port))

    print("Requesting tunnel")

    # Start key exchange
    send_with_length(data_sock, b"tunnel")

    # Send client public key
    send_with_length(data_sock, public_key_bytes)

    # Receive server public key
    server_pub_bytes = recv_with_length(data_sock)

    # Convert to RSA key
    server_public_key = import_public_key(server_pub_bytes)

    print("Server public key received")
    print("Tunnel established")

    print("Encrypting message:", MESSAGE)

    # Encrypt message using server public key
    encrypted_msg = encrypt_message(MESSAGE, server_public_key)

    print("Sending encrypted message:", encrypted_msg)

    # Send post command
    send_with_length(data_sock, b"post")

    # Send encrypted message
    send_with_length(data_sock, encrypted_msg)

    # Receive encrypted hash
    encrypted_hash = recv_with_length(data_sock)

    print("Received hash")

    # Decrypt hash
    server_hash = decrypt_message(encrypted_hash, private_key)

    # Optional tamper simulation
    if tamper:
        server_hash = server_hash[:-1] + ("0" if server_hash[-1] != "0" else "1")

    print("Computing hash")

    # Compute local hash
    local_hash = compute_sha256(MESSAGE)

    # Compare results
    if server_hash == local_hash:
        print("Secure")
    else:
        print("Compromised")

    data_sock.close()


if __name__ == "__main__":
    main()
