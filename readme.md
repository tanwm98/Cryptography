# Secure Proximity Detection Application

## Overview
This application allows users to check if their friends are nearby without revealing their exact locations. The system uses the "Pierre Protocol" which implements secure proximity testing using EC ElGamal encryption.

## Features
- User registration and authentication
- Friend request system
- Privacy-preserving location sharing
- Two proximity metrics:
  - Grid-based (same cell detection)
  - Euclidean distance-based (configurable threshold)

## Components
- Server: Handles user accounts, friend relationships, and message forwarding
- Client: User interface for registration, login, location updates, and proximity checks
- Cryptographic module: Implements EC ElGamal for secure proximity testing

## Security Features
- Elliptic curve cryptography (SECP256k1)
- Homomorphic encryption for location privacy
- Secure key exchange
- Message integrity through HMAC
- Password hashing with Argon2

## Technical Details
- Implementation of the Pierre Protocol for privacy-preserving proximity testing
- Ephemeral key pairs for each location request
- Homomorphic properties to compute distances without revealing locations
- Grid-based space division (1000×1000 units per cell)
- Extended Euclidean distance calculations for more precise proximity detection

## Requirements
- Python 3.x
- Required libraries:
  - ecdsa
  - cryptography
  - argon2-cffi

## Installation and Usage
1. Install the required dependencies
   ```
   pip install ecdsa cryptography argon2-cffi
   ```
2. Start the server
   ```
   python server.py
   ```
3. Start the client
   ```
   python client.py
   ```
4. Follow the on-screen prompts to register, login, add friends and check proximity

## Project Structure
- `server.py`: Server implementation
- `client.py`: Client application
- `elgamal.py`: Implementation of the Pierre Protocol using EC ElGamal

## Authors
ALOYSIUS JUNIOR, DANIEL CHUA EE HERNG, GAN YI HENG JOEL, WAN WEILON, 
ONG ZHI KANG, TAN WEI MING, TAY ZHI YI 
