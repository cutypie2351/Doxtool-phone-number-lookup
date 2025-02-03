import base64
import gzip
import io
import os
import time
import re
import httpx
import requests
from hashlib import md5
from colorama import Fore, Style
import json
import urllib.parse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

from io import BytesIO
import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
import json as jsond
import random


class init_func:
    def clear():
        if platform.system() == 'Windows':
            os.system('title Doxtool - made by Cutypie')
        elif platform.system() == 'Linux':
            sys.stdout.write("\x1b]0;Doxtool - made by Cutypie\x07")
        elif platform.system() == 'Darwin':
            os.system('''echo - n - e "\033]0;Doxtool - made by Cutypie\007"''') 


    



    


    def start(self):
        print(Fore.GREEN + "[*] Loading some stuff, please wait..." + Style.RESET_ALL)

        init_func.clear()

        def getchecksum():
            md5_hash = hashlib.md5()
            file = open(''.join(sys.argv), "rb")
            md5_hash.update(file.read())
            digest = md5_hash.hexdigest()
            return digest

        os.system('cls')
       




class Sync_Me:
    # The RSA public key in Base64
    RSA_PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Lvdi42MyxXYABWyCDAbvejbaaE1Uv05ECIr8VChTbi+kHlqgd+faZF/4VTDnWR2ARBx/P4d1jnL8j7akknJkukuVZHjVFU/X7Zi9F/aq/TeJ1FvezfiwFy58z1+p3g694MS39alzvf3uIPGDRxxOPiV9D/uVcbv70BAkNu9D71ToqONRq1bJB7Wy20oW7Nb+IrSHFexINf1q9QFfWmFelEzwXE9D6/04gu191kVoWeR/hlGXW5MnRCPedhQQgz8giVIbD/MXoM9PsRAKTyrkFYJ5g5QE0/oMRkBqIXCT/Wk54u5Gw91Nq5Bc5lOtNpddgOyZjG1K/USys7giur7HwIDAQAB"

    def compress_if_needed(self, phone_number):
        test_string = f'{{"phone":"{phone_number}","manufacturer":"Asus","model":"ASUS_Z01QD","version_code":28,"action":"search","locale":"en_US","get_hints":true,"is_search":true,"ACCESS_TOKEN":"FDGAVufRo6Ujn8APNNzixYKeLfJFYXEoaFMl764JyBY","APPLICATION_ID":"8a078650-5acd-11e1-b86c-0800200c9a66","X-device-info":"Asus,ASUS_Z01QD,9","APPLICATION_VERSION":"4.44.6.2","version_number":497,"phone_number":"{phone_number}"}}'
        bytes_data = test_string.encode('utf-8')
        if len(bytes_data) >= 200:
            compressed = gzip.compress(bytes_data)
            return compressed
        return bytes_data

    def encode_data(self, data):
        # Generate a random AES key
        aes_key = os.urandom(16)  # AES key size: 128 bits
        
        # Generate a random IV
        iv = os.urandom(16)  # IV size: 128 bits for AES

        # Initialize AES cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data using AES
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Combine encrypted data and IV
        array = encrypted_data + iv

        # Create the header key
        public_key = load_der_public_key(base64.b64decode(self.RSA_PUBLIC_KEY_BASE64))

        # Encrypt the AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encode the encrypted AES key using Base64 to create the header key
        header_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        return array, header_key

    @staticmethod
    def send_post_request(header_key, request_body, more):
        # Define the headers
        headers = {
            "X-SyncME-gzip": "true",
            "X-SyncME-Key": header_key,
            "X-SyncME-Android-Number": "497",
            "Content-Length": str(len(request_body)),
            "Host": "api.sync.me",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "Sync.ME Android 4.44.6.2"
        }

        # Send the POST request
        url = "https://api.sync.me/api/caller_id/caller_id/v2"
        response = requests.post(url, headers=headers, data=request_body)

        # Print the response status and content
        # print("Response Status:", response.status_code)
        # ... existing code ...

        # Parse and decode the JSON response content
        response_data = response.content.decode('utf-8')
        response_json = json.loads(response_data)

        
        # Properly decode the garbled text in the 'name' field assuming it's encoded in Windows-1255
        if 'name' in response_json:
            corrected_name = response_json['name'].replace('\\\\', '\\')

        if 'show_ads' in response_json:
            del response_json['show_ads']

        if 'ads_platform' in response_json:
            del response_json['ads_platform']

        if 'error_code' in response_json:
            del response_json['error_code']

        if 'error_description' in response_json:
            del response_json['error_description']

        if 'premium_type' in response_json:
            del response_json['premium_type']

        # Check if response_json is a list and get the first item if it is
        if isinstance(response_json, list) and len(response_json) > 0:
            response_json = response_json[0]

        if isinstance(response_json, dict):
            # Properly decode the garbled text in the 'name' field assuming it's encoded in Windows-1255
            if 'name' in response_json:
                corrected_name = response_json['name'].replace('\\\\', '\\')

            # ... (rest of the code for removing unwanted fields)

            if more:
                print("DataBase 2 Information:\n", json.dumps(response_json, ensure_ascii=False, indent=4))
            else:
                # print(Fore.LIGHTGREEN_EX + f"[+] Found Name: {name}" + Style.RESET_ALL)
                print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 2):" + Style.RESET_ALL)
                # print("DataBase 2 Information:\n", json.dumps(response_json, ensure_ascii=False, indent=4))
                name = response_json.get('name', '')
                    
                if name:
                    print(Fore.LIGHTGREEN_EX + "[+] Found Name (DataBase 2): " + name + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't find Name in - (DataBase 2):")
                picture = response_json.get('picture', '')
                if picture:
                    print(Fore.LIGHTGREEN_EX + "[+] Found Picture (DataBase 2): " + picture + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't find Picture in - (DataBase 2):")
                country = response_json.get('geospace', '{}').get('country', '')
                if country:
                    print(Fore.LIGHTGREEN_EX + "[+] Found Country (DataBase 2): " + country + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't find Country in - (DataBase 2):")
                spam_count = response_json.get('spam', '')
                if spam_count:
                    print(Fore.LIGHTGREEN_EX + "[+] Found Spam Count (DataBase 2): " + str(spam_count) + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't find Spam Count in - (DataBase 2):")
                big_spammer = response_json.get('big_spammer', '')
                if big_spammer:
                    print(Fore.LIGHTGREEN_EX + "[+] Found if Big Spammer (DataBase 2): " + str(big_spammer) + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't if Big Spammer in - (DataBase 2):")

                networks = response_json.get('networks', [])
                if isinstance(networks, list) and networks:
                    network = networks[0]  # Get the first network
                    networks_firstname = network.get('first_name', '')
                    if networks_firstname:
                        print(Fore.LIGHTGREEN_EX + "[+] Found networks first name (DataBase 2): " + networks_firstname + Style.RESET_ALL)

                    networks_lastname = network.get('last_name', '')
                    if networks_lastname:
                        print(Fore.LIGHTGREEN_EX + "[+] Found networks last name (DataBase 2): " + networks_lastname + Style.RESET_ALL)
                    
                    networks_picture = network.get('thumbnail', '')
                    if networks_picture:
                        print(Fore.LIGHTGREEN_EX + "[+] Found networks picture (DataBase 2): " + networks_picture + Style.RESET_ALL)
                    
                    networks_sn_id = network.get('sn_id', '')
                    if networks_sn_id:
                        print(Fore.LIGHTGREEN_EX + "[+] Found networks sn_id (DataBase 2): " + networks_sn_id + "\n" + Style.RESET_ALL)
                # else:
                #     print("[-] Couldn't find networks_sn_id in - (DataBase 2):")

        else:
            print(Fore.RED + "Unexpected response format from DataBase 2" + Style.RESET_ALL)


        # if 'premium_metadata' in response_json and 'relationships' in response_json['premium_metadata']:
        #    del response_json['premium_metadata']['relationships']

        # if 'name' in response_json:
        #    response_json['full_name'] = response_json.pop('name')

        # Print the decoded response JSON
        #print("DataBase 2 Response:\n", json.dumps(response_json, ensure_ascii=False, indent=4))
       


    def start_styncme(self, input, more):
        syncme = Sync_Me()
        compressed_bytes = syncme.compress_if_needed(input)

        # Use the (compressed or original) data for encryption
        encoded_data, header_key = syncme.encode_data(compressed_bytes)

        # Send the POST request
        syncme.send_post_request(header_key, encoded_data, more)



class CallerID:
    

    def start_callerid_check(self, input, more):

        def generate_stamp(phone_number, id_value, package_name, unique_id, hex_value):
            input_string = f"{phone_number}{id_value}{package_name}{unique_id}{hex_value}"
            md5_hash = md5()
            md5_hash.update(input_string.encode('utf-8'))
            return md5_hash.hexdigest()
    
        r0_v = -1
        current_time_seconds = int(time.time())
        rn = str(current_time_seconds - r0_v)
        phone_number_2 = "+" + input

        phone_build = phone_number_2
        phone_number = phone_build + rn
        package_name = "com.callblocker.whocalledme"
        unique_id = "7861d4c119ec0f35"
        hex_value = "cfebad501698c7d4"  # Derived from the intermediate steps

        stamp = generate_stamp(phone_number, "", package_name, unique_id, hex_value)

        # Part 2: Encoding (from encode.py)
        def l(bArr, i10, i11, i12):
            if bArr is None:
                raise ValueError("Cannot serialize a null array.")
            if i10 < 0:
                raise ValueError("Cannot have negative offset: {}".format(i10))
            if i11 < 0:
                raise ValueError("Cannot have length offset: {}".format(i11))
            if i10 + i11 > len(bArr):
                raise ValueError("Cannot have offset of {} and length of {} with array of length {}".format(i10, i11, len(bArr)))

            if (i12 & 2) != 0:
                byte_array_output_stream = io.BytesIO()
                try:
                    gzip_output_stream = gzip.GzipFile(fileobj=byte_array_output_stream, mode="wb")
                    gzip_output_stream.write(bArr[i10:i10 + i11])
                    gzip_output_stream.close()
                    return byte_array_output_stream.getvalue().decode('utf-8')
                except Exception as e:
                    raise e
            else:
                z10 = (i12 & 8) != 0

                i14 = (i11 // 3) * 4
                i13 = 4 if i11 % 3 > 0 else 0
                i15 = i14 + i13
                if z10:
                    i15 += i15 // 76

                i16 = i15
                bArr2 = bytearray(i16)
                i17 = i11 - 2
                i18 = 0
                i19 = 0
                i20 = 0

                while i18 < i17:
                    h(bArr, i18 + i10, 3, bArr2, i19, i12)
                    i22 = i20 + 4
                    if z10 and i22 >= 76:
                        bArr2[i19 + 4] = 10
                        i19 += 1
                        i20 = 0
                    else:
                        i20 = i22
                    i18 += 3
                    i19 += 4

                if i18 < i11:
                    h(bArr, i18 + i10, i11 - i18, bArr2, i19, i12)
                    i19 += 4

                if i19 <= i16 - 1:
                    return bArr2[:i19].decode('utf-8')
                return bArr2.decode('utf-8')

        def h(bArr, offset, length, output, out_offset, options):
            base64_encoded = base64.b64encode(bArr[offset:offset + length])
            output[out_offset:out_offset + len(base64_encoded)] = base64_encoded



        def l(bArr, i10, i11, i12):
            if bArr is None:
                raise ValueError("Cannot serialize a null array.")
            if i10 < 0:
                raise ValueError("Cannot have negative offset: {}".format(i10))
            if i11 < 0:
                raise ValueError("Cannot have length offset: {}".format(i11))
            if i10 + i11 > len(bArr):
                raise ValueError("Cannot have offset of {} and length of {} with array of length {}".format(i10, i11, len(bArr)))

            if (i12 & 2) != 0:  # Equivalent to checking if the 2nd bit is set
                byte_array_output_stream = io.BytesIO()
                try:
                    gzip_output_stream = gzip.GzipFile(fileobj=byte_array_output_stream, mode="wb")
                    gzip_output_stream.write(bArr[i10:i10 + i11])
                    gzip_output_stream.close()
                    return byte_array_output_stream.getvalue().decode('utf-8')
                except Exception as e:
                    raise e
            else:
                z10 = (i12 & 8) != 0  # Equivalent to checking if the 8th bit is set

                i14 = (i11 // 3) * 4
                i13 = 4 if i11 % 3 > 0 else 0
                i15 = i14 + i13
                if z10:
                    i15 += i15 // 76

                i16 = i15
                bArr2 = bytearray(i16)
                i17 = i11 - 2
                i18 = 0
                i19 = 0
                i20 = 0

                while i18 < i17:
                    h(bArr, i18 + i10, 3, bArr2, i19, i12)
                    i22 = i20 + 4
                    if z10 and i22 >= 76:
                        bArr2[i19 + 4] = 10
                        i19 += 1
                        i20 = 0
                    else:
                        i20 = i22
                    i18 += 3
                    i19 += 4

                if i18 < i11:
                    h(bArr, i18 + i10, i11 - i18, bArr2, i19, i12)
                    i19 += 4

                if i19 <= i16 - 1:
                    return bArr2[:i19].decode('utf-8')
                return bArr2.decode('utf-8')

        def h(bArr, offset, length, output, out_offset, options):
            # This is the actual base64 encoding part
            base64_encoded = base64.b64encode(bArr[offset:offset + length])
            output[out_offset:out_offset + len(base64_encoded)] = base64_encoded

        # Example usage:
        str_value = phone_number_2
        bArr = bytearray(str_value, 'utf-8')  # Convert the string to a bytearray (equivalent to str.getBytes() in Java)
        i10 = 0
        i11 = len(bArr)  # Length of the bytearray
        i12 = 0
        result = l(bArr, i10, i11, i12)

        def a(str_input):
            return str_input

        def c(str_input):
            sb = []
            char_array = list(str_input)
            # print(char_array)
            
            # print("Character transformation:")
            for i11, char in enumerate(char_array):
                c10 = ord(char)
                # print(f"  Original: {char} (ASCII: {c10})")
                
                if (48 <= c10 <= 57) or (65 <= c10 <= 90) or (97 <= c10 <= 122):
                    i12 = (i11 % 5) + c10
                    # print(f"    Shift: {i12}")
                    
                    if i12 > 122:
                        i10 = (i12 - 122) + 47
                    elif c10 <= 90 and i12 > 90:
                        i10 = (i12 - 90) + 96  # Changed from 97 to 96
                    elif c10 <= 57 and i12 > 57:
                        i10 = (i12 - 57) + 65
                    else:
                        i10 = i12
                    
                    c10 = i10
                
                # print(f"    After processing: {chr(c10)} (ASCII: {c10})")
                sb.append(a(chr(c10)))
            
            result2 = ''.join(sb)
            # print(f"Final result: {result}")
            return result2

        # Example usage:
        input_str = result  # The base64 encoded string already provided
        encode_tel_number = c(input_str)
        # print(f"Final Result: {encode_tel_number}")  # The result should match the Java function output.


        # print(encode_tel_number)
        # print(stamp)




        modified_tel_number = encode_tel_number[:1] + '0' + encode_tel_number[2:]
        encoded_tel_number_final = urllib.parse.quote(modified_tel_number)

        # print(encoded_tel_number_final)

        # print(encoded_tel_number_final)
        # Raw data for the request body with appended static strings
        raw_data = f"cc=972&uid=6578ca99978b447e8ebeb08354e6cec1&tel_number={encoded_tel_number_final}&stamp={stamp}&device=android&version=1.7.1&default_cc=972&cid="

        # Define headers
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(raw_data)),
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/3.14.9"
        }

        # Send the POST request
        response = requests.post("https://app.aunumber.com/api/v1/sea.php", data=raw_data, headers=headers)


        def reverse_c(encoded_str):
            # This function is the reverse of the shifting operation performed in `c`.
            sb = []
            byte_array = bytearray(encoded_str, 'utf-8')
            
            for i11 in range(len(byte_array)):
                c10 = byte_array[i11]
                if (48 <= c10 <= 57) or (65 <= c10 <= 90) or (97 <= c10 <= 122):
                    i12 = c10 - (i11 % 5)
                    
                    if i12 < 48:
                        i12 = 122 - (47 - i12)
                    elif c10 >= 97 and i12 < 97 and i12 > 57:
                        i12 = 90 - (96 - i12)
                    elif c10 >= 65 and i12 < 65 and i12 > 47:
                        i12 = 57 - (64 - i12)
                        
                    c10 = i12
                sb.append(str(c10))
            
            return ','.join(sb)

        def decode_a(encoded_str):
            # This function is the reverse of the `a` function.
            try:
                return ''.join(chr(int(c)) for c in encoded_str.split(','))
            except Exception as e:
                print(f"An error occurred in decode_a: {e}")
                return None

        def decode_l(encoded_str):
            # This function reverses the `l` function.
            try:
                bArr = bytearray(base64.b64decode(encoded_str))
                return bArr.decode('utf-8')
            except Exception as e:
                print(f"An error occurred in decode_l: {e}")
                return None

        # Example usage:

        # Given encoded value
        encoded_value = response.text

        # Step 1: Reverse the `c` function
        shifted_back = reverse_c(encoded_value)

        # Step 2: Reverse the `a` function (if needed)
        decoded_a_value = decode_a(shifted_back)

        if decoded_a_value:
            # Step 3: Reverse the `l` function (to get the original string)
            final_result = decode_l(decoded_a_value)
            if final_result:
                try:
                    json_object = json.loads(final_result)
                    if more:
                        print("\nDataBase 1 Information:")
                        print(json.dumps(json_object, indent=4) + "\n")
                    else:
                        name = json_object.get('name', '')
                        picture = json_object.get('avater', '')
                        location = json_object.get('belong_area', '')
                        address = json_object.get('address', '')
                        report_count = json_object.get('report_count', '')
                        old_tel_number = json_object.get('old_tel_number', '')
                        type_num = json_object.get('type_label', '')
                        
                        print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 1): " + Style.RESET_ALL)
                        if name:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Name (DataBase 1): " + name + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Name in - (DataBase 1):")
                        if picture:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Picture (DataBase 1): " + picture + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Picture in - (DataBase 1):")
                        if location:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Location (DataBase 1): " + location + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Location in - (DataBase 1):")
                        if address:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Address (DataBase 1): " + address + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Address in - (DataBase 1):")
                        if report_count:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Report Count (DataBase 1): " + str(report_count) + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Report Count in - (DataBase 1):")
                        if old_tel_number:
                            print(Fore.LIGHTGREEN_EX + "[+] Found Old Phone Number (DataBase 1): " + str(old_tel_number) + Style.RESET_ALL)

                        if type_num:
                            print(Fore.LIGHTGREEN_EX + "[+] Found the Type of the Number (DataBase 1): " + type_num + Style.RESET_ALL)
                        # else:
                        #     print("[-] Couldn't find Old Phone Number in - (DataBase 1):\n")

                    
                    # print("\nCaller ID Response:")
                    # print(json.dumps(json_object, indent=4) + "\n")
                except json.JSONDecodeError:
                    print(Fore.RED + "Failed to parse the response as JSON." + Style.RESET_ALL)
                    # print(f"Raw response: {final_result}")
            else:
                print(Fore.RED + "Failed to decode the base64 string in decode_l." + Style.RESET_ALL)

        else:
            print(Fore.RED + "Failed to decode the string in decode_a." + Style.RESET_ALL)



class CallApp:
    

    
    def send_request(self, phone_number, more):

        url = f"https://s.callapp.com/callapp-server/csrch?cpn=%2B{phone_number}&myp=gp.106898501948939491020&ibs=0&cid=0&tk=0011243853&cvc=2206"
        

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Host": "s.callapp.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        
        try:
            response = requests.get(url, headers=headers)
            try:
                cout = 0
                response_data = response.content.decode('utf-8')
                response_json = json.loads(response_data)
                if more:
                    print("DataBase 3 Information:")
                    print(json.dumps(response_json, ensure_ascii=False, indent=2))
                else:
                    # print(Fore.LIGHTGREEN_EX + "     [2] Help" + Style.RESET_ALL)
                    print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 3):" + Style.RESET_ALL)
                    name = response_json.get('name', '')
                    priority = response_json.get('priority', '')
                    website = response_json.get('websites', '')
                    address = response_json.get('addresses', '')
                    picture = response_json.get('photoUrl', '')
                    categories = response_json.get('categories', '')
                    description = response_json.get('description', '')
                    business_url = response_json.get('url', '')
                    facebookID = response_json.get('facebookID', '')
                    if name:
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Name: {name}" + Style.RESET_ALL)
                        cout += 1
                    if picture:
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Picture: {picture}" + Style.RESET_ALL)
                        cout += 1
                    if description:
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Description: {description}" + Style.RESET_ALL)
                        cout += 1
                    if business_url:
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Business Url: {business_url}" + Style.RESET_ALL)
                        cout += 1
                    if facebookID:
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Facebook Profile Data: {facebookID}" + Style.RESET_ALL)
                        print(Fore.LIGHTGREEN_EX + f"[+] Found Facebook Profile Link: https://www.facebook.com/profile.php?id={facebookID['id']}" + Style.RESET_ALL)
                        cout += 1
                    if website:
                        cout += 1
                        if len(website) > 0:
                            websiteurl1 = website[0].get('websiteUrl', '')
                            print(Fore.LIGHTGREEN_EX + f"[+] Found Website: {websiteurl1}" + Style.RESET_ALL)
                        if len(website) > 1:
                            websiteurl2 = website[1].get('websiteUrl', '')
                            if websiteurl2:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Website 2: {websiteurl2}" + Style.RESET_ALL)
                    if address:
                        cout += 1
                        if len(address) > 0:
                            address1 = address[0].get('street', '')
                            print(Fore.LIGHTGREEN_EX + f"[+] Found Street: {address1}" + Style.RESET_ALL)
                        if len(address) > 1:
                            address2 = address[1].get('street', '')
                            if address2:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Street 2: {address2}" + Style.RESET_ALL)
                    if categories:
                        cout += 1
                        if len(categories) > 0:
                            categories1 = categories[0].get('name', '')
                            print(Fore.LIGHTGREEN_EX + f"[+] Found categorie: {categories1}" + Style.RESET_ALL)
                    

                    if priority:
                        cout += 1
                        print(Fore.LIGHTGREEN_EX + f"[+] Found priority: {priority}" + Style.RESET_ALL)
                    
                    if cout > 3:
                        print(Fore.YELLOW + f"[+] Found a lot if Data, Use 'More Info' to get all the data!" + Style.RESET_ALL)
                
                # response_j = response.json()
                # json_contant = response.content
                
            except Exception as content_error:
                if more:
                    print("\nDataBase 3 Information:")
                else:
                    print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 3):" + Style.RESET_ALL)
                    print(Fore.RED + f"No Data Found" + Style.RESET_ALL)
            
            return response
        
        except requests.RequestException as e:
            print(Fore.RED + f"An error occurred while sending the request: {e}" + Style.RESET_ALL)


class Eyecon:
    def send_request_pic(self, phone_number, more):
        url_getpic = f"https://api.eyecon-app.com/app/pic?cli={phone_number}&is_callerid=true&size=big&type=0&src=MenifaFragment&cancelfresh=0&cv=vc_538_vn_4.0.538_a"
        
        headers_getpic = {
            "Cache-Control": "no-cache",
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "e-auth-v": "e1",
            "e-auth": "4e728c50-2991-424e-9b74-2edae43f1b3a", 
            "e-auth-c": "21",
            "e-auth-k": "PgdtSBeR0MumR7fO",
            "Host": "api.eyecon-app.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
        }

        session = requests.Session()
        response = session.get(url_getpic, headers=headers_getpic, allow_redirects=False)  # Disable auto-redirect
        try:
            if more:
                print("\nDataBase 4 Information 1:")
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    print(f"\nPicture Link: {redirect_url}\n")
            else:

                print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 4):" + Style.RESET_ALL)
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    print(Fore.LIGHTGREEN_EX + f"[+] Picture Link Found: {redirect_url}\n" + Style.RESET_ALL)
                    match = re.search(r"graph\.facebook\.com/(\d+)/picture", redirect_url)
                    facebook_id = match.group(1)
                    if facebook_id:
                        print(Fore.LIGHTGREEN_EX + f"[+] Facebook Profile Link Found: https://www.facebook.com/profile.php?id={facebook_id}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[-] No Picture Found" + Style.RESET_ALL)
            return response
        except Exception as e:
            print(Fore.RED + f"\nError: {e}" + Style.RESET_ALL)
            return None

    def send_request_getname(self, phone_number, more):
        url_getname = f"https://api.eyecon-app.com/app/getnames.jsp?cli={phone_number}&lang=en&is_callerid=true&is_ic=true&cv=vc_538_vn_4.0.538_a&requestApi=URLconnection&source=MenifaFragment"
        
        headers_getname = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
            "accept" : "application/json",
            "e-auth-v": "e1",
            "e-auth": "4e728c50-2991-424e-9b74-2edae43f1b3a",
            "e-auth-c": "21",
            "e-auth-k": "PgdtSBeR0MumR7fO",
            "accept-charset":"UTF-8",
            "content-type":"application/x-www-form-urlencoded; charset=utf-8",
            "Host": "api.eyecon-app.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        try:
            response = requests.get(url_getname, headers=headers_getname)
            response_j = response.json()
            if more:
                
                print("\nDataBase 4 Information 2:")
                print(json.dumps(response_j, ensure_ascii=False, indent=2))
            else:
                if response.content:
                    if len(response_j) > 0:
                        name = response_j[0].get('name', '')
                        type = response_j[0].get('type', '')
                        if name:
                            print(Fore.LIGHTGREEN_EX + f"[+] Found Name: {name}" + Style.RESET_ALL)
                        if type:
                            print(Fore.RED + f"[+] Found Type: {type}" + Style.RESET_ALL)
                    # print(json.dumps(response_j, ensure_ascii=False, indent=2))
                else:
                    print(Fore.RED + f"[-] No Data Found" + Style.RESET_ALL)
            
            return response
        except Exception as e:
            print(f"Error: {e}")
            return None

            
class Truecaller:
   
    def find_value_in_list(data_list, tab_name):
        for item in data_list:
            if isinstance(item, dict) and tab_name in item:
                return item[tab_name]  # Return first occurrence of key
        return None  # Return None if key not found

    
    

    def send_request(self, phone_number, more):
        tokens = [
            "Bearer a2i0t--ncJeSVF-VYZg3zGmFzQGZh-rY_c2B16r31IFj9Ie9ql6LVzF8p7KronlL"
        ]  
         
        headers_truecaller = {
            "accept": "application/json",
            "authorization": tokens[0],
            "accept-encoding": "gzip",
            "user-agent": "Truecaller/14.40.7 (Android;11)"
        }
        url = f"https://search5-noneu.truecaller.com/v2/search?q={phone_number}&countryCode=IL&type=4&locAddr=&encoding=json"
        try:
            
            if more:
                with httpx.Client(http2=True, timeout=10.0) as client:
                    response = client.get(url, headers=headers_truecaller)
                    print("\nDataBase 5 Information:")
                    if response.status_code == 200:
                        try:
                            response_j = response.json()
                            print("Response Data:")
                            print(json.dumps(response_j, indent=2, ensure_ascii=False))
                        except json.JSONDecodeError:
                            print("Response Data (Raw):")
                            print(response.text)
                    else:
                        print("Error Response Data:")
                        print(response.text)
            else:
                print(Fore.LIGHTBLACK_EX + "\n[*] Checking in (DataBase 5):" + Style.RESET_ALL)
                with httpx.Client(http2=True, timeout=10.0) as client:
                    response = client.get(url, headers=headers_truecaller)
                    
                    response_j = response.json()
                    data_list = response_j.get('data', '')
                    json_data = data_list[0]
                    name = json_data.get('name', '')
                    gender = json_data.get('gender', '')
                    addr_list = json_data.get('internetAddresses', '')
                    email = None
                    if addr_list:
                        email = Truecaller.find_value_in_list(addr_list, 'id')
                    tags = json_data.get('tags', '')
                    score = json_data.get('score', '')
                    picture = json_data.get('image', '')
                    phones_list = json_data.get('phones', '')
                    carreir = None
                    if phones_list:
                        carreir = Truecaller.find_value_in_list(phones_list, 'carrier')
                    spaminfo = json_data.get('spamInfo', '')
                    spamtype = None
                    if spaminfo:
                        spamtype = spaminfo.get('spamType', '')
                    addresses_list = json_data.get('addresses', '')
                    area = None
                    city = None
                    Time = None
                    if addresses_list:
                        area = Truecaller.find_value_in_list(addresses_list, 'area')
                        city = Truecaller.find_value_in_list(addresses_list, 'city')
                        Time = Truecaller.find_value_in_list(addresses_list, 'timeZone')



                    if response.status_code == 200:
                        try:
                            if name:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Name: {name}" + Style.RESET_ALL)
                            if picture:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Picture Link: {picture}" + Style.RESET_ALL)
                            if gender:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Gender: {gender}" + Style.RESET_ALL)
                            if email:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Email: {email}" + Style.RESET_ALL)
                            if tags:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Tags: {tags}" + Style.RESET_ALL)
                            if score:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Score: {score}" + Style.RESET_ALL)
                            if carreir:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Carreir: {carreir}" + Style.RESET_ALL)
                            if spaminfo:
                                print(Fore.RED + f"[+] Is Spammer: True" + Style.RESET_ALL)
                            else:
                                print(Fore.GREEN + f"[+] Is Spammer: False" + Style.RESET_ALL)
                            if area:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Area: {area}" + Style.RESET_ALL)
                            if city:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found City: {city}" + Style.RESET_ALL)
                            if Time:
                                print(Fore.LIGHTGREEN_EX + f"[+] Found Time: {Time}" + Style.RESET_ALL)
                            
                            # print(json.dumps(response_j, indent=2, ensure_ascii=False))
                        except json.JSONDecodeError:
                            print(Fore.RED + f"[-] Error with server response" + Style.RESET_ALL)
                            # print(response.text)
                    else:
                        print(Fore.RED + "Error Response Data:" + Style.RESET_ALL)
                        #print(response.text)

                    return response

        except Exception as e:
            print(Fore.RED + f"error found: {e}" + Style.RESET_ALL)
            return None
        




class Menu:


    def banner(self):
        print("")
        print("▓█████▄  ▒█████  ▒██   ██▒ ▄▄▄█████▓ ▒█████   ▒█████   ██▓    ")
        print("▒██▀ ██▌▒██▒  ██▒▒▒ █ █ ▒░ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ")
        print("░██   █▌▒██░  ██▒░░  █   ░ ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ")
        print("░▓█▄   ▌▒██   ██░ ░ █ █ ▒  ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    ")
        print("░▒████▓ ░ ████▓▒░▒██▒ ▒██▒   ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒")
        print(" ▒▒▓  ▒ ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░")
        print(" ░ ▒  ▒   ░ ▒ ▒░ ░░   ░▒ ░     ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░")
        print(" ░ ░  ░ ░ ░ ░ ▒   ░    ░     ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ")
        print("   ░        ░ ░   ░    ░                ░ ░      ░ ░      ░  ░")
        print(" ░                made by 'cutypie.' on dc                    ")
        print("") 

    def check_exit():
        input_exit = input("[*] Do you want to continue? (y/n): ")
        if input_exit.lower() in ["y", "Y", "yes", "Yes", "YES"]:
            return False
        else:
            return True
    def check_more():
        input_exit = input("\n[*] Do you want more informations? (y/n): ")
        if input_exit.lower() in ["y", "Y", "yes", "Yes", "YES"]:
            return True
        else:
            return False
    
    def start(self):
        exit_rn = False
        syncme = Sync_Me()
        callerid = CallerID()
        callapp = CallApp()
        eyecon = Eyecon()
        truecaller = Truecaller()
        
        
        print("\n[*] Menu:\n")
        print(Fore.LIGHTBLACK_EX + "     [1] Phone Number Checker" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "     [2] Help" + Style.RESET_ALL)
        print(Fore.RED + "     [3] Exit" + Style.RESET_ALL)
        input_select = input("\n[*] Select Option: ")
        if input_select.lower() in ["1"]:
            phone_number = input("[*] Enter Phone Number: ")
            callerid.start_callerid_check(phone_number, False)
            syncme.start_styncme(phone_number, False)

            callapp.send_request(phone_number, False)
            eyecon.send_request_pic(phone_number, False)
            eyecon.send_request_getname(phone_number, False)
            truecaller.send_request(phone_number, False)

            more_ = Menu.check_more()
            if more_:
                callerid.start_callerid_check(phone_number, True)
                syncme.start_styncme(phone_number, True)
                callapp.send_request(phone_number, True)
                eyecon.send_request_pic(phone_number, True)
                eyecon.send_request_getname(phone_number, True)
                truecaller.send_request(phone_number, True)
                
            exit_ = Menu.check_exit()
            if exit_:
                exit_rn = True
        if input_select.lower() in ["2"]:
            print(Fore.LIGHTGREEN_EX + "\nPhone Number Format Example: (IL: 972501111111), (US: 11234567890), etc...\n\nRead Me:\n[*] Phone Number Checker Detials:\n\nPhone Number Checker is an Dox tool that will show you some information about the phone number.\nfor example: name, location, picture, address, if hes a spammer and more...\nUse At Your Own Risk!!! Enjoy!\n" + Style.RESET_ALL)
            # print("\nPhone Number Format Example: (IL: 972501111111), (US: 11234567890), etc...\n\nRead Me:\n[*] Phone Number Checker Detials:\n\nPhone Number Checker is an Dox tool that will show you some information about the phone number.\nfor example: name, location, picture, address, if hes a spammer and more...\nUse At Your Own Risk!!! Enjoy!\n")
            exit_ = Menu.check_exit()
            if exit_:
                exit_rn = True

        elif input_select.lower() in ["3"]:
            exit_rn = True

        os.system('cls')

        return exit_rn





if __name__ == "__main__":
    try:
        main_menu = Menu()
        init_ = init_func()
        main_menu.banner()
        init_.start()
        
        while True:
            main_menu.banner()
            menu = main_menu.start()

            if menu:
                break

    except Exception as e:
        print(f"An error found: {e}")
