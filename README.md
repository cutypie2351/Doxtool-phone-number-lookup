# Doxtool-phone-number-lookup
Doxtool is a Python tool made by Cutypie, This tool gives you the ability to reverse phone number lookups.
The tool sending multiple caller id request to their databases using encrypt and decrypt request body technology that include more then 4 Layers of encryptions.

## What does it do?
- Gets information about phone numbers from 2 different databases
- Shows names, pictures, and locations connected to the number
- Checks if the number is used for spam
- Shows social media profiles if available

## Features
- Profile Picture
- First Name, Last Name
- Location Address
- Facebook Profile Data
- Facebook Profile Link
- Is a Spammer
- Country
- Description
- Business Website
- Opening Hours Business
- Street
- Jobs
- Google Map Places Coords
- Region
- Report count
- Old phone number
- Phone type
- Etc...


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

**Sync.ME** also have a website you can use with limited search (https://sync.me/)

### Database 3 (CallApp):
- hashing
- URL Encoding
- GZIP compression

### Database 4 (Eyecon):
- auth keys header hashing
- URL Encoding
- GZIP compression

### Database 5 (Truecaller):
- auth token header generation
- URL Encoding
- GZIP compression

**Truecaller** also have a website you can use with limited search (https://www.truecaller.com/)

## How I Made It
### CallerID App (Database 1)
- I analyzed their API request to understand how the security work and how the data sent (Headers, stamp, base64 phone number format, etc...)
- I used ADB to dump the app, then found an encryption native library ".so" file exstention.
- I used IDA to reverse the native library and found the encryption process the app is using
- Using jadx-gui + Frida to hook another encryption layer function of the request body data that using shifting algorithm to make it harder to reverse
- Made a full python script that Decrypt all of this process and get the clear decoded data from the database.

### SyncMe App (Database 2)
-  I analyzed their API request also to understand the request format and the security usage.
-  Found that thet using multiple of layers encryptions using Frida tool such us:
  * AES-128: for the request body encryption
  * RSA: for the AES key
  * Custom request Stamping algorithm
  * GZIP compression: for large requests
  * Made a full python script that Decrypt all of this process and get the clear decoded data from the database.

### CallApp, Eyecon, Truecaller (Database 3, 4, 5)
- This databases added in the new version (23/01/2025) by Me
- I Found the request format + hooked the functions for auth headers, hashing and more to make the script work

## How to Install
1. Clone this repository
2. Install requirements:
```bash
pip install -r requirements.txt
