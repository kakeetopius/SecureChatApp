# Secure Chat Application Documentation

## Table of Contents

- [Overview](#1-overview)
- [Features](#2-features)
- [System Architecture](#3-system-architecture)
- [Installation Guide](#4-installation-guide)
- [Usage Instructions](#5-usage-instructions)
- [Protocol Implementation](#6-protocol-implementation)

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

---

## 3. System Architecture

### 3.1 Client-Server Model

#### Server Component

- Connection Management: Handles multiple simultaneous client connections
- Message Routing: Directs encrypted messages to appropriate recipients
- User Authentication: Validates credentials and manages sessions
- Active Client Tracking: Maintains real-time user presence information

#### Client Component

- Starts a Graphical User Interface: Tkinter-based desktop application
- Connects to server and authenticate.
- Listens for updates from the server in a different thread.
- Send updates from listening thread to a queue.
- Main thread processes queue and updates gui

[Client Architecture](resources/client_arch.png)

---

## 4. Installation Guide

### 4.1 Prerequisites

#### Requirements

Python Version: 3.7 or higher  
uv python package manager  
Operating System: Windows, macOS, or Linux

### 4.2 Installation Steps

#### 1. Repository Setup

```bash
git clone https://github.com/kakeetopius/SecureChatApp.git
cd SecureChatApp
```

#### 2. Cryptographic Key Generation

If the utility `make` is available in the PATH, run the following at the root of the project.

```bash
make certs
```

OR:

##### Generate server private key (2048-bit RSA)

```bash
openssl genrsa -out server_privkey.pem 2048
```

##### Extract server public key

```bash
openssl rsa -in server_privkey.pem -pubout -out server_pubkey.pem
```

---

## 5. Usage Instructions

### 5.1 Server Operation

Starting the Server

```bash
#create the environmnt
uv sync

#start the server to listen on a particular
uv run server.py -p 9000
#default port (if not given) is 9876

#get help
uv run server.py -h
```

### 5.2 Client Operation

Starting Client Application

```bash
#start client and provide port server is listening to. Default is 9876
uv run gui.py -p 9000

#get help
uv run gui.py -h
```

---

## 6. Protocol Implementation

### 6.1 Authentication Protocol

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

### 6.2 Message Encryption and Exchange Protocol

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

> [!NOTE]
> **For a visual of the message flow [Click here](resources/message_flow.png)**

### 6.3 Message Format

1. Length Prefix: 4-byte big-endian message length header
2. JSON Payload: Structured data format for all communications with a _command_ field specifying what operation is being carried out.  
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
