# Secure Chat Application Documentation

## Table of Contents
- [Overview](#overview)  
- [Features](#features)  
- [System Architecture](#system-architecture)  
- [Installation Guide](#installation-guide)  
- [Usage Instructions](#usage-instructions)
- [GUI Framework](#gui-framework)
- [Protocol Implementation](#protocol-implementation)

## 1. Overview
The Secure Chat Application is a real-time messaging platform that implements end-to-end encryption using standard cryptographic protocols. Built with Python and Tkinter, this application provides secure communication channels between users. 

### Key Characteristics
- Real-time Communication: Instant message delivery between online users
- End-to-End Encryption: Ensures message confidentiality and integrity
- Cross-Platform Compatibility: Runs on Windows, macOS, and Linux systems
- Educational Focus: Demonstrates secure software development practices
 
---
## 2. Features
   
 #### Security Features
 - RSA Public Key Encryption (2048-bit): Secures credential transmission and key exchange processes
 - AES-256 Session Keys: Provides efficient symmetric encryption for message content
 - Bcrypt Password Hashing: Implements secure password storage with salt
 - End-to-End Encryption: Guarantees only intended recipients can decrypt and read messages
 - Message Authentication Codes (MAC): Ensures message integrity and authenticity

 #### Chat Functionality
 - Real-time Messaging: Instant delivery of encrypted messages between users
 - User Authentication System: Secure login and registration processes
 - Dynamic User Presence: Real-time online/offline status updates

 #### Technical Capabilities
 - SQLite Database Integration: Efficient user management and data persistence
 - Non-blocking Socket Communication: Optimized network performance
 - JSON-based Message Protocol: Structured and extensible data exchange format
 - Modular Code Design: Maintainable and extensible codebase structure

___
## 3. System Architecture
   
### 3.1 Client-Server Model
#### Server Component
 - Connection Management: Handles multiple simultaneous client connections
 - Message Routing: Directs encrypted messages to appropriate recipients
 - User Authentication: Validates credentials and manages sessions
 - Active Client Tracking: Maintains real-time user presence information

#### Client Component
 - Graphical User Interface: Tkinter-based desktop application
 - Cryptographic Operations: Handles encryption and decryption processes
 - Server Communication: Manages network connectivity and message exchange

### 3.2 Encryption Flow
#### 1. Initialization Phase  
* Clients generate RSA-2048 key pairs upon startup   
* Server maintains persistent RSA key pair for secure handshakes  

 #### 2. Authentication Phase  
* Client sends user credentials encrypted with server's public RSA key to server  
 
 #### 3. Key Exchange Phase  
* Clients generate unique AES-256 session keys for each peer  
* Session keys exchanged via RSA-encrypted channels before first message is sent  

 #### 4. Message Exchange Phase   
* Sender client encrypts message and includes a Message Authentication Code(HMAC) for the encrypted message.     
*  Receiver client verifies HMAC and decrypts message with already established session key.  
* This ensures both integrity and confidentiality.  

___
## 4. Installation Guide
   
### 4.1 Prerequisites
#### System Requirements  
  Python Version:  3.7 or higher  
  Operating System:  Windows, macOS, or Linux  
  Disk Space:  About 30 MB available space  
  Memory:  Minimum 512 MB RAM  

Required Python Packages
```bash
pip install pycryptodome bcrypt
```


### 4.2 Installation Steps
#### 1. Repository Setup

```bash
git clone https://github.com/kakeetopius/SecureChatApp.git
cd SecureChat
```

#### 2. Cryptographic Key Generation  

##### Generate server private key (2048-bit RSA)
```bash
  openssl genrsa -out server_privkey.pem 2048
```
    
##### Extract server public key
```bash
openssl rsa -in server_privkey.pem -pubout -out server_pubkey.pem
```

####  3. Database Initialization  
The SQLite database (securechat.db) is automatically initialized with the required schema upon first server execution.

___
## 5. Usage Instructions
   
### 5.1 Server Operation

Starting the Server
```bash
  python server.py
```

### 5.2 Client Operation
Starting Client Application
```bash
  python gui.py
```
  
---
## 6. GUI Framework
Tkinter Interface: Main window and component management  
Frame Classes:  

  1. LoginFrame: Authentication interface  
  2. SignupFrame: User registration interface  
  3. ChatFrame: Main messaging interface  

Network Communication  
  1. Queue System: Thread-safe message processing  
  2. Event Handling: Real-time UI updates from network events  
  3. Encryption Management: RSA and AES cryptographic operations  

--- 
## 7. Protocol Implementation
   
### 7.1 Authentication Protocol

#### Login Process
  1. Client encrypts username/password with server's public RSA key and submits together with their public key.  
  2. Server decrypts credentials using private RSA key  
  3. System verifies credentials against bcrypt hashes in database  
  4. Successful authentication grants session access  

#### Registration Process
  1. Client submits encrypted registration data  
  2. Server verifies username availability  
  3. System hashes password with bcrypt and salt  
  4. New user record created in database  

### 7.2 Message Encryption Protocol

#### Session Establishment
  1. Client generates AES-256 session key for each peer
  2. Session key encrypted with peer's public RSA key
  3. Encrypted session key transmitted via server relay
  4. Peer decrypts session key with private RSA key

#### Message Exchange
  1. Sender encrypts message with AES session key
  2. Message includes initialization vector (IV) and MAC
  3. Encrypted payload transmitted via server
  4. Recipient decrypts using session key and verifies integrity

### 7.3 Message Format
  1. Length Prefix: 4-byte big-endian message length header
  2. JSON Payload: Structured data format for all communications with a *command* field specifying what operation is being carried out.  
     For example, to send a message the payload would look something like this.
     ```json
        {
            "command": "send_message",
            "username": "pius",
            "peername": "victor",
            "message": "b64_encrypted_message",
            "iv": "b64_iv",
            "mac": "b64_mac_bytes"
        }

     ```

> [!NOTE]
>Disclaimer
>This software is provided for educational purposes. Users are responsible for ensuring compliance with local laws and regulations when deploying secure communication systems. The authors assume no liability for damages resulting from the use or misuse of this application.
>
>Document Version: 1.0
>Last Updated: 11/6/2025
>Compatible With: Application Version 1.0
