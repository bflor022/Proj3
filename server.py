import socket
from crypto import *

HOST = '127.0.0.1'
PORT = 8080


"""
send_with_length(sock, data)

Purpose:
    Sends a complete message using length prefix.
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
    # TODO:
    # Implement a blocking read loop that returns exactly n bytes.
    #
    # What this function must do:
    # 1. Create an empty bytes buffer
    # 2. Repeatedly call sock.recv(...) requesting only the remaining bytes
    # 3. Append each chunk to the buffer
    # 4. If recv() returns empty bytes before completion, raise:
    #      ConnectionError("Socket connection closed unexpectedly")
    # 5. Return the completed buffer once its length is n
    raise NotImplementedError("TODO: implement recv_exact")


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

    # Accept control connection
    control_conn, _ = server.accept()

    with control_conn:
        # Expect "connect"
        command = recv_with_length(control_conn).decode().strip()

        if command != "connect":
            raise ValueError("Expected connect")

        print("Connection requested. Creating data socket")

        # Create data socket
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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

            # Receive client public key
            client_pub_bytes = recv_with_length(data_conn)
            client_public_key = import_public_key(client_pub_bytes)

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

            # Decrypt message
            message = decrypt_message(encrypted_msg, private_key)

            print("Decrypted message:", message)

            print("Computing hash")

            # Compute hash
            hash_val = compute_sha256(message)

            # Encrypt hash with client public key
            encrypted_hash = encrypt_message(hash_val, client_public_key)

            print("Responding with hash:", hash_val)

            # Send encrypted hash
            send_with_length(data_conn, encrypted_hash)

        data_socket.close()

    server.close()


if __name__ == "__main__":
    main()
