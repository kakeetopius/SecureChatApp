import socket
import json
import time 
import struct
import select
from base64 import b64encode, b64decode

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import HMAC, SHA256


class Client():
    """
    Secure Chat Client - Handles encrypted communication with server and peers.
    
    Features:
    - RSA encryption for server authentication
    - AES session keys for peer-to-peer encryption
    - HMAC for message integrity verification
    - Non-blocking socket communication
    - GUI integration via callbacks
    """
    
    def __init__(self, on_message=None):
        """Initialize client with encryption keys and connection settings."""
        # Network configuration
        self.client_socket = None
        self.server_port = 9876
        self.server_address = "localhost"

        # User credentials and keys
        self.username = ""
        self.password = ""
        self.private_key: RSA.RsaKey = None
        self.public_key: RSA.RsaKey = None
        self.peers: list[Client_Peer] = []  # List of connected peers

        # Load server's public key for secure authentication
        self.server_public_key = self.import_server_pubkey("server_pubkey.pem")

        if not self.server_public_key:
            print("Could not get server public key")
            
        # Callback function for GUI updates
        self.on_message = on_message

        # Generate client's RSA keypair
        self.gen_keypair()

    def import_server_pubkey(self, pub_key_path):
        """
        Load server's RSA public key from PEM file.
        
        Args:
            pub_key_path: Path to server's public key file
            
        Returns:
            RSA.RsaKey: Server's public key object
        """
        pub_key = None

        if pub_key_path:
            with open(pub_key_path, "rb") as f:
                pub_key_data = f.read()
                pub_key = RSA.import_key(pub_key_data)

        return pub_key

    def dial_server(self):
        """Establish connection to the chat server."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.client_socket.settimeout(10)

            # Connect to server
            self.client_socket.connect((self.server_address, self.server_port))
            self.client_socket.setblocking(False)  # Non-blocking for polling

            print("Connected to server")
        except Exception as e:
            raise ConnectionError(f"Failed to Connect to Server on {self.server_address}:{self.server_port} - {e}")

    def poll_server(self):
        """
        Check for incoming messages from server using non-blocking I/O.
        
        Uses select() to efficiently handle multiple connections without blocking.
        """
        sockets2poll = [self.client_socket]
        buffers = {self.client_socket: b''}  # Buffer for incomplete messages
        
        try:
            readable, _, _ = select.select(sockets2poll, [], [], 0)
            for sock in readable:
                if sock == self.client_socket:
                    data = sock.recv(4096)
                    if not data:
                        print("Server closed Connection")
                        return
                    
                    # Append received data to buffer
                    buffers[sock] += data
                    self.process_buffer(sock, buffers)
                    
        except KeyboardInterrupt:
            print("Stopping Client")
            self.client_socket.close()

    def process_buffer(self, sock, buffers):
        """
        Process buffered data to extract complete messages.
        
        Message format: [4-byte length][json message data]
        Handles partial messages by buffering until complete.
        """
        buf = buffers[sock]
        while True:
            # Check if we have enough data for message length header
            if len(buf) < 4:
                break       # not enough to read header

            # Extract message length (big-endian 4-byte integer)
            msg_len = struct.unpack(">I", buf[:4])[0]
            
            # Check if complete message has been received
            if len(buf) < 4 + msg_len:
                break # full message not yet received

            # Extract complete message from buffer
            msg_data = buf[4: 4+msg_len]
            # Remove processed message from buffer
            buf = buf[4+msg_len:]
            
            self.process_message(msg_data)
            
        # Update buffer with remaining data
        buffers[sock] = buf

    def process_message(self, msg_bytes) -> int:
        """
        Route incoming messages to appropriate handlers based on command.
        
        Supported commands from server:
        - auth_denied/auth_granted: Authentication responses
        - recv_message: Encrypted messages from peers
        - recv_session_key: Session keys for P2P encryption
        - new_peer/close_peer: Peer connection/disconnection notifications
        """
        msg = json.loads(msg_bytes.decode("utf-8"))
        print(f"Received message: {msg}")
        
        command = msg["command"]

        match command:
            case "auth_denied" | "auth_granted":
                self.handle_auth_response(command, msg)
            case "recv_message":
                self.receive_message(msg)
            case "recv_session_key":
                self.receive_session_key(msg)
            case "new_peer":
                self.handle_new_peer(msg)
            case "close_peer":
                self.remove_peer(msg)
            case _:
                print(f"Got unknown command: {command}")

    def gen_keypair(self):
        """Generate client's RSA keypair for secure communication."""
        self.private_key = RSA.generate(3072)  # 3072-bit RSA for strong security
        self.public_key = self.private_key.public_key()

    def gen_sessionkey(self, peer: Client_Peer) -> bytes:
        """
        Generate and encrypt session key for peer-to-peer communication.
        
        Process:
        1. Generate random 32-byte AES-256 session key
        2. Encrypt with peer's RSA public key
        3. Store session key locally for future use
        
        Args:
            peer: Target peer for session key exchange
            
        Returns:
            bytes: RSA-encrypted session key
        """
        # 32 byte session key for AES-256
        session_key = Crypto.Random.get_random_bytes(32)

        # Convert session key to base64 for storage
        session_key_b64 = b64encode(session_key).decode("utf-8")

        # Store the session key as string in base64
        peer.session_key = session_key_b64

        # Encrypt session key using peer's RSA public key
        cipher_rsa = PKCS1_OAEP.new(peer.public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        return encrypted_session_key

    def send_encrypted_message(self, peer_username, message):
        """
        Send encrypted message to peer using established session key.
        
        Security features:
        - AES-256 in CBC mode for encryption
        - PKCS7 padding for block alignment
        - HMAC-SHA256 for message integrity
        - Automatic session key exchange if needed
        
        Args:
            peer_username: Recipient's username
            message: Plaintext message to encrypt and send
        """
        # Convert message to bytes
        message = message.encode("utf-8")

        # Look up session key for the peer
        session_key_b64 = None
        for peer in self.peers:
            if peer.name == peer_username:
                session_key_b64 = peer.session_key
                if not session_key_b64:
                    # If no session key yet, first generate and send it
                    self.send_session_key(peer)
                    # Wait for 2 seconds for key exchange to complete
                    time.sleep(2)
                    session_key_b64 = peer.session_key
                break 

        if session_key_b64 is None:
            print(f"No peer: {peer_username}")
            return 

        # Convert base64 session key back to bytes
        session_key_bytes = b64decode(session_key_b64)

        # Encrypt message using session key with AES-CBC
        cipher_aes = AES.new(session_key_bytes, AES.MODE_CBC)
        encrypted_message_bytes = cipher_aes.encrypt(pad(message, AES.block_size)) 

        # Generate HMAC authentication code for IV and encrypted message
        hmac_obj = HMAC.new(session_key_bytes, digestmod=SHA256)
        hmac_obj.update(cipher_aes.iv + encrypted_message_bytes)
        mac_bytes = hmac_obj.digest() 
        
        # Convert IV, cipher text, and MAC to base64 for transmission
        b64_iv = b64encode(cipher_aes.iv).decode("utf-8")
        b64_encrypted_message = b64encode(encrypted_message_bytes).decode("utf-8")
        b64_mac_bytes = b64encode(mac_bytes).decode("utf-8")

        # Prepare message for server routing
        data = {
            "command": "send_message",
            "username": self.username,
            "peername": peer_username,
            "message": b64_encrypted_message,
            "iv": b64_iv,
            "mac": b64_mac_bytes
        }

        self.send_to_server(data)
        
    def send_session_key(self, peer: Client_Peer):
        """
        Initiate session key exchange with a peer.
        
        The session key is encrypted with the peer's RSA public key
        and forwarded through the server for secure delivery.
        """
        # Get peer's public key
        peer_pub_key = None
        peer_username = peer.name
        peer_pub_key = peer.public_key

        if peer_pub_key is None:
            print(f"Don't have public key for {peer_username}")
            return

        # Generate and encrypt session key
        enc_session_key = self.gen_sessionkey(peer)

        # Convert encrypted session key to base64
        session_key = b64encode(enc_session_key).decode("utf-8")

        # Request server to forward session key to peer
        data = {
            "command": "exchange_session_key",
            "username": self.username,
            "peername": peer_username,
            "session_key": session_key
        }

        self.send_to_server(data)

    def send_login_request(self):
        """
        Send login request with encrypted credentials.
        
        Security:
        - Username and password encrypted with server's RSA public key
        - Base64 encoding for safe JSON transmission
        - Includes client's public key for future P2P communication
        """
        # Export client's public key as PEM string
        public_key_pem = self.public_key.export_key().decode("utf-8")

        # Encrypt username and password with server's public key
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        enc_username = cipher_rsa.encrypt(self.username.encode("utf-8"))
        enc_password = cipher_rsa.encrypt(self.password.encode("utf-8"))

        # Convert encrypted data to base64 for JSON transmission
        b64_enc_username = b64encode(enc_username).decode("utf-8")
        b64_enc_password = b64encode(enc_password).decode("utf-8")

        # Prepare login request
        data = {
            "command": "login",
            "username": b64_enc_username,
            "password": b64_enc_password,
            "public_key": public_key_pem
        }

        self.send_to_server(data)

    def send_signup_request(self):
        """
        Send signup request with encrypted credentials.
        
        Uses same encryption scheme as login for consistency.
        """
        # Export client's public key as PEM string
        public_key_pem = self.public_key.export_key().decode("utf-8")

        # Encrypt username and password with server's public key
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        enc_username = cipher_rsa.encrypt(self.username.encode("utf-8"))
        enc_password = cipher_rsa.encrypt(self.password.encode("utf-8"))

        # Convert encrypted data to base64 for JSON transmission
        b64_enc_username = b64encode(enc_username).decode("utf-8")
        b64_enc_password = b64encode(enc_password).decode("utf-8")

        # Prepare signup request
        data = {
            "command": "signup",
            "username": b64_enc_username,
            "password": b64_enc_password,
            "public_key": public_key_pem
        }

        self.send_to_server(data)

    def handle_auth_response(self, command, data: dict):
        """
        Process authentication response from server.
        
        Args:
            command: "auth_granted" or "auth_denied"
            data: Response data including peer list if successful
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if command == "auth_denied":
            self.send_to_gui("show_auth_error", None)
            return False
        
        # Authentication successful - process peer list
        for peer in data["peers"]:
            peer_pub_key = peer["public_key"]
            # Extract public key from PEM format
            peer_pub_key = RSA.import_key(peer_pub_key.encode("utf-8"))
            self.peers.append(Client_Peer(peer["username"], peer_pub_key))
            self.send_to_gui("add_active_user", peer["username"])

        # Notify GUI to show chat interface
        self.send_to_gui("show_chat", self.username)
        return True

    def handle_new_peer(self, data: dict):
        """
        Handle notification of new peer connecting to server.
        
        Adds new peer to local peer list and notifies GUI.
        """
        peer_pub_key = data["public_key"]

        # Extract public key from PEM format
        peer_pub_key = RSA.import_key(peer_pub_key.encode("utf-8"))

        # Add new peer to local list
        self.peers.append(Client_Peer(data["peername"], peer_pub_key))
        self.send_to_gui("add_active_user", data["peername"])

    def remove_peer(self, data: dict):
        """
        Handle notification of peer disconnection.
        
        Removes peer from local list and notifies GUI.
        """
        name = data["peername"]

        for peer in self.peers:
            if peer.name == name:
                self.peers.remove(peer)
                print(f"Peer: {name} is removed")
                break
        
        self.send_to_gui("remove_active_user", data["peername"])

    def receive_message(self, data: dict):
        """
        Process incoming encrypted message from peer.
        
        Security verification steps:
        1. Verify HMAC for message integrity
        2. Decrypt message with session key
        3. Remove PKCS7 padding
        
        Args:
            data: Message data containing encrypted content, IV, and MAC
        """
        iv = data["iv"]
        message = data["message"]
        mac = data["mac"]
        peer_name = data["peername"]

        # Convert message, IV and MAC from base64 to bytes
        encrypted_message = b64decode(message)
        iv = b64decode(iv)
        mac = b64decode(mac)

        # Find peer's session key
        session_key = None
        for peer in self.peers:
            if peer.name == peer_name:
                session_key = peer.session_key
                break

        # If no session key found
        if not session_key:
            print(f"Could not get session_key for {peer_name}")
            return

        # Convert base64 session key back to bytes
        session_key_bytes = b64decode(session_key)

        try:
            # Verify message integrity using HMAC
            hmac_obj = HMAC.new(session_key_bytes, digestmod=SHA256)
            hmac_obj.update(iv + encrypted_message)
            hmac_obj.verify(mac)  # Raises ValueError if MAC doesn't match

            # Decrypt message using session key
            cipher_aes = AES.new(key=session_key_bytes, mode=AES.MODE_CBC, iv=iv)
            padded_decrypted_message = cipher_aes.decrypt(encrypted_message)
            
            # Remove PKCS7 padding
            decrypted_message = unpad(padded_decrypted_message, AES.block_size)

            print(f"Message from {peer_name}: {decrypted_message}")

            # Send decrypted message to GUI for display
            self.send_to_gui("display_message", (peer_name, decrypted_message.decode("utf-8")))
            
        except ValueError:
            print("ERROR: Message integrity check failed or could not decrypt.")

    def receive_session_key(self, data: dict) -> bool:
        """
        Process incoming session key from peer.
        
        The session key is encrypted with this client's RSA public key
        and needs to be decrypted with the private key.
        
        Args:
            data: Contains encrypted session key and peer information
            
        Returns:
            bool: True if session key successfully processed, False otherwise
        """
        peer_name = data["peername"]
        session_key = data["session_key"]

        for peer in self.peers:
            if peer.name == peer_name:
                # Decrypt session key with client's private key
                cipher_rsa = PKCS1_OAEP.new(self.private_key)
                encrypted_session_key = b64decode(session_key)
                decrypted_session_key = cipher_rsa.decrypt(encrypted_session_key)
    
                # Store decrypted session key in base64 format
                peer.session_key = b64encode(decrypted_session_key).decode("utf-8")
                
                print(f"Session key for {peer_name} successfully added")
                return True

        return False

    def send_to_server(self, data: dict):
        """
        Send data to server using length-prefixed JSON format.
        
        Format: [4-byte message length][JSON message data]
        
        Args:
            data: Dictionary to send as JSON
        """
        # Convert dictionary to JSON bytes
        data = json.dumps(data).encode("utf-8")
        
        # Prepend message length (big-endian unsigned int)
        data_len = struct.pack(">I", len(data))

        # Send length header followed by message data
        self.client_socket.sendall(data_len + data)

    def send_to_gui(self, msg, data=None):
        """
        Send message to GUI via callback function.
        
        Args:
            msg: Message type/command for GUI
            data: Optional data payload
        """
        if self.on_message:
            self.on_message(msg, data)


class Client_Peer():
    """
    Represents a connected peer in the chat system.
    
    Stores peer information including public key and session key
    for secure peer-to-peer communication.
    """
    def __init__(self, peer_name: str, public_key: RSA.RsaKey):
        self.name = peer_name
        self.public_key: RSA.RsaKey = public_key
        self.session_key: str = None  # Stored in base64 format

    def get_publickey(self):
        return self.public_key

    def set_publickey(self, public_key):
        self.public_key = public_key
