# Doxtool-phone-number-lookup
Doxtool is a Python tool made by Cutypie, This tool gives you the ability to reverse phone number lookups.
The tool sending multiple caller id request to their databases using encrypt and decrypt request body technology that include more then 4 Layers of encryptions.

## What does it do?
- Gets information about phone numbers from 2 different databases
- Shows names, pictures, and locations connected to the number
- Checks if the number is used for spam
- Shows social media profiles if available


## Encryption Used
### Database 1 (CallerID):
- MD5 hash for security
- Base64 encoding
- Custom text shifting
- GZIP compression

### Database 2 (SyncMe):
- AES encryption (128 bit)
- RSA encryption for keys
- Random IV generation
- PKCS7 padding


## How to Install
1. Clone this repository
2. Install requirements:
```bash
pip install -r requirements.txt
