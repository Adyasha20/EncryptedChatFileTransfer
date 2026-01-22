## Encrypted Chat & File Transfer System

A secure, deployable Java desktop application that enables encrypted file transfer over a local network (LAN).  
The project demonstrates real-world use of cryptography, secure networking, and software deployment concepts.

---

## Features

- Secure file transfer over LAN
- Supports **text files, PDFs, and images**
- End-to-end encryption using hybrid cryptography
- Sender and Receiver GUI modes
- Integrity verification to prevent tampering
- Deployable as an executable `.jar` file

---

## Security Architecture

- **AES (CBC mode)** for fast symmetric file encryption  
- **RSA-2048** for secure AES session key exchange  
- **SHA-256** for file integrity verification  
- Hybrid encryption workflow inspired by **TLS**

---

## Tech Stack

- **Language:** Java  
- **GUI:** Java Swing  
- **Cryptography:** AES, RSA, SHA-256  
- **Networking:** Java Sockets  
- **Tools:** Git, GitHub  

---

## Project Structure

EncryptedChatFileTransfer/
│
├── src/
│   ├── CryptoUtils.java
│   ├── NetworkUtils.java
│   ├── GUI.java
│   ├── Main.java
│
├── dist/
│   └── EncryptedChatFileTransfer.jar
│
├── .gitignore
├── README.md


