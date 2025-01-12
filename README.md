# End-to-End Encrypted Messaging Protocol (EE2E)
**By Liron Karni and Eitan Kot**

---

## Introduction
The proposed protocol aims to ensure secure and reliable communication between clients in an environment where threats to privacy and data confidentiality are increasing. It is specifically designed to protect personal data, ensure the identity of communication participants, and allow for the secure exchange of encryption keys between clients.

---

## Protocol Objective
The primary goal of the protocol is to establish a secure communication channel between clients using advanced cryptographic techniques. The protocol ensures that communication details are protected from adversaries (MITM), while maintaining data integrity and mutual authentication of participant identities.

---

## Protocol Importance
- **Privacy and Confidentiality:** Utilizes strong encryption mechanisms (AES-256, RSA) to prevent unauthorized access to message content.
- **Participant Identity Verification:** Digital signatures and HMAC ensure that each participant is who they claim to be.
- **Resistance to Attacks:** Protects against common attacks like Man-in-the-Middle (MITM) and message forgery.
- **Offline Support:** If a participant is offline, the server stores messages until the participant reconnects.

---

## Key Actions in the Protocol
- **Registration and Authentication:** Secure client registration with the server, including cryptographic key generation and identity verification using OTP.
- **Key Exchange:** Structured process for securely transferring encryption keys between clients with identity verification.
- **Message Sending:** Encrypting messages, maintaining message integrity using HMAC, and transmitting via a secure server.
- **Acknowledgment Sending:** Built-in mechanism for acknowledgment delivery, including mutual verification.

With this protocol, communication is guaranteed to occur in a secure environment protected from potential threats while ensuring transparency and compatibility for users.

---

## Step 1: Client Registration and Initial Authentication

### 1.1 Registration Request
- The client sends a registration request to the server along with their phone number.

### 1.2 Sending OTP
- The server sends a one-time password (OTP) to the client via a secure channel (SMS).
- The OTP is valid for 5 minutes only.

### 1.3 Generating Keys on the Client Side
- Each client generates an RSA key pair:
  - The private and public keys are stored locally.
  - The public key is sent to the server, and the private key is used for decryption and signing.

### 1.4 Creating a Shared Salt
- The server and client generate an identical Salt using HMAC:
  - `HMAC-SHA256(PhoneNumber, OTP) = Salt`

### 1.5 Generating a Temporary Cryptographic Key (K_temp)
- The client and server generate the same `K_temp` using KDF:
  - `PBKDF2(OTP, Salt, Iterations, KeyLength) = K_temp`

### 1.6 Sending Public Key and Verification
- The client:
  1. Computes a digital signature for their public key using `K_temp` and HMAC:
     - `HMAC-SHA256(PublicKey, K_temp) = Signature`
  2. Sends the following to the server:
     - Public Key
     - Signature

- The server:
  1. Independently computes the signature for the client's public key.
  2. Compares the computed signature with the received one.
  3. If the signatures match and the OTP is within the 5-minute validity, the client's public key is stored in a table with their identifier (phone number).

---

## Step 2: Key Exchange Between Clients A and B

### 2.1 Initiating a New Session Request
- Client A informs the server they wish to initiate communication with Client B.

### 2.2 Verifying Client B's Availability
- The server verifies that Client B exists and is available.

### 2.3 Transmitting Client B's Public Key to Client A
- The server:
  1. Applies SHA-256 to Client B's public key and encrypts it using the server's private key to create a signature.
  2. Sends the following to Client A:
     - Public Key of Client B.
     - Signature created by the server.

### 2.4 Verifying the Public Key Sent to Client A
- Client A:
  1. Decrypts the signature using the server's public key.
  2. Applies SHA-256 to the public key received from the server and compares it to the decrypted signature.
  3. If they match, the key is verified and stored.

### 2.5 Generating a Symmetric Key and Signature
- Client A:
  1. Generates a random symmetric key `K`.
  2. Encrypts `K` in two steps:
     - First, with Client B's public key.
     - Second, applies a SHA-256 hash to `K` and encrypts it with Client A's private key to create a digital signature.
  3. Sends to the server:
     - The symmetric key `K` encrypted with Client B's public key.
     - The digital signature.

### 2.6 Server Actions
- The server:
  - Applies SHA-256 to Client A's public key and encrypts it using the server's private key.

### 2.7 Transmitting the Symmetric Key and Public Key of Client A to Client B
- The server sends to Client B:
  - The encrypted symmetric key and signature received from Client A.
  - Client A's public key and the signature generated by the server.

### 2.8 Verifying the Public Key Sent to Client B
- Client B:
  1. Decrypts the signature using the server's public key.
  2. Applies SHA-256 to the public key received from the server and compares it to the decrypted signature.
  3. If they match, the public key is verified and stored.

### 2.9 Decrypting and Verifying the Symmetric Key
- Client B:
  1. Decrypts the encrypted symmetric key using their private key.
  2. Applies SHA-256 to `K`, decrypts the signature using Client A's public key, and compares the results for verification.
  3. If verification is successful, the symmetric key is stored in an external file.

---

## Step 3: Sending Messages

### 3.1 Encrypting the Message
- Client A:
  1. Writes a message `M`.
  2. Encrypts `M` using the symmetric key with AES-256.
  3. Computes `HMAC-SHA256` using the symmetric key and `M`.
  4. Generates a new `IV`.

### 3.2 Sending the Message
- The client sends to the server:
  - `M_encrypted`: The encrypted message.
  - `HMAC`: The message signature.
  - `IV`.

- The server:
  - Receives the message but cannot decrypt it.
  - Checks if Client B is connected and forwards the message to Client B without changes.
  - If Client B is not connected, the server stores the message in a table until the client connects.

### 3.3 Decrypting and Verifying the Message on Client B
- Client B:
  1. Decrypts `M_encrypted` using the symmetric key and the `IV`.
  2. Computes `HMAC` and compares it to the received value.
  3. If the values match, the message is verified and read.

---

## Step 4: Sending an Acknowledgment (ACK)

### 4.1 Creating the ACK
- Client B:
  1. Creates an acknowledgment message (`ACK`).
  2. Signs the `ACK` using `HMAC-SHA256` with the symmetric key.

### 4.2 Sending the ACK to the Server
- The client sends the `ACK` and its signature to the server.

### 4.3 Forwarding the ACK to Client A
- The server forwards the `ACK` and its signature to Client A.

### 4.4 Verifying the ACK
- Client A:
  1. Creates a signature for the received `ACK` using `HMAC-SHA256` and the symmetric key.
  2. Compares the generated signature with the received one.
  3. If the signatures match, the acknowledgment is accepted.

---


