import socket
from crypto import *

HOST = '127.0.0.1'
PORT = 8080

"""
This server uses two TCP sockets:
1. a control socket on the fixed port for the initial "connect" command
2. a temporary data socket for the tunnel and post steps
This matches the project requirement that the server first accepts a
connection request, then responds with a different port for data exchange.
"""

"""
send_with_length(sock, data)

Purpose:
    Sends a complete message using length prefix.

TCP does not preserve message boundaries by itself.
A 4-byte length prefix is added so the receiver knows exactly
how many bytes belong to one command or encrypted payload.
"""

def send_with_length(sock, data):
    # Convert payload length to a 4-byte header
    length = len(data).to_bytes(4, 'big')

    # Send the header followed by the payload
    sock.sendall(length + data)


"""
recv_exact(sock, n)

Purpose:
    Receives exactly n bytes from socket.
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
    Receives length-prefixed message.
"""
def recv_with_length(sock):
    # Read the 4-byte length prefix first
    length_data = recv_exact(sock, 4)

    # Convert the length header into an integer
    length = int.from_bytes(length_data, 'big')

    # Read and return exactly that many payload bytes
    return recv_exact(sock, length)


"""
main()

Purpose:
    Server workflow:
    - Accept connection
    - Exchange keys
    - Receive encrypted message
    - Decrypt and hash
    - Return encrypted hash
"""
def main():
    print("Starting server...")
    print("Creating RSA keypair")

    # Generate server keys
    private_key, public_key = generate_keys()

    # Convert public key to bytes
    public_key_bytes = export_public_key(public_key)

    print("RSA keypair created")
    print("Creating server socket")

    # Create socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow quick restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind and listen
    server.bind((HOST, PORT))
    server.listen(1)

    print("Awaiting connections...")

    """
    The first socket only handles the initial handshake.
    The client must first send "connect" on this control connection
    before the server creates the separate data socket.
    """
    
    # Accept control connection
    control_conn, _ = server.accept()

    with control_conn:
        # Expect "connect"
        command = recv_with_length(control_conn).decode().strip()

        if command != "connect":
            raise ValueError("Expected connect")

        print("Connection requested. Creating data socket")

        """
        A separate data socket is created after the connect command.
        This socket is used for the tunnel and post phases of the project.
        """
        
        # Create data socket
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        """
        Port 0 tells the OS to automatically choose any free port.
        The server then sends that chosen port number back to the client.
        """
        
        data_socket.bind((HOST, 0))
        data_socket.listen(1)

        # Send assigned port
        data_port = data_socket.getsockname()[1]
        send_with_length(control_conn, str(data_port).encode())

        # Accept data connection
        data_conn, _ = data_socket.accept()

        with data_conn:
            # Expect "tunnel"
            command = recv_with_length(data_conn).decode().strip()

            if command != "tunnel":
                raise ValueError("Expected tunnel")

            print("Tunnel requested. Sending public key")

            """
            During the tunnel step, the client sends its public key first.
            The server stores it so it can later encrypt the response hash
            in a way that only that client can decrypt.
            """
            
            # Receive client public key
            client_pub_bytes = recv_with_length(data_conn)
            client_public_key = import_public_key(client_pub_bytes)

            """
            The server now sends its own public key to complete the tunnel setup.
            After this exchange, both sides have the public key needed to send
            encrypted data securely to the other side.
            """
            
            # Send server public key
            send_with_length(data_conn, public_key_bytes)

            # Expect "post"
            command = recv_with_length(data_conn).decode().strip()

            if command != "post":
                raise ValueError("Expected post")

            print("Post requested.")

            # Receive encrypted message
            encrypted_msg = recv_with_length(data_conn)

            print("Received encrypted message:", encrypted_msg)

            """
            The ciphertext was encrypted with the server's public key,
            so only the server's private key can recover the original message.
            """
            
            # Decrypt message
            message = decrypt_message(encrypted_msg, private_key)

            print("Decrypted message:", message)

            print("Computing hash")

            """
            The server hashes the decrypted plaintext to create an integrity value.
            If the client computes the same SHA-256 hash locally, the message was
            received and processed correctly.
            """
            
            # Compute hash
            hash_val = compute_sha256(message)

            """
            The hash is encrypted with the client's public key before being returned.
            That means only the client can decrypt the response with its private key.
            """
            
            # Encrypt hash with client public key
            encrypted_hash = encrypt_message(hash_val, client_public_key)

            print("Responding with hash:", hash_val)

            # Send encrypted hash
            send_with_length(data_conn, encrypted_hash)

        data_socket.close()

    server.close()


if __name__ == "__main__":
    main()
