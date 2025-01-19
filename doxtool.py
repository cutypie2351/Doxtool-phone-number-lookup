import base64
import gzip
import io
import os
import time
import requests
from hashlib import md5
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


class init_func:
    def clear():
        if platform.system() == 'Windows':
            os.system('title Doxtool - made by Cutypie')
        elif platform.system() == 'Linux':
            sys.stdout.write("\x1b]0;Doxtool - made by Cutypie\x07")
        elif platform.system() == 'Darwin':
            os.system('''echo - n - e "\033]0;Doxtool - made by Cutypie\007"''') 


    



    


    def start(self):
        print("[*] Loading some stuff, please wait...")

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
                print("\n[*] Checking in (DataBase 2):")
                # print("DataBase 2 Information:\n", json.dumps(response_json, ensure_ascii=False, indent=4))
                name = response_json.get('name', '')
                    
                if name:
                    print("[+] Found Name (DataBase 2): " + name)
                # else:
                #     print("[-] Couldn't find Name in - (DataBase 2):")
                picture = response_json.get('picture', '')
                if picture:
                    print("[+] Found Picture (DataBase 2): " + picture)
                # else:
                #     print("[-] Couldn't find Picture in - (DataBase 2):")
                country = response_json.get('geospace', '{}').get('country', '')
                if country:
                    print("[+] Found Country (DataBase 2): " + country)
                # else:
                #     print("[-] Couldn't find Country in - (DataBase 2):")
                spam_count = response_json.get('spam', '')
                if spam_count:
                    print("[+] Found Spam Count (DataBase 2): " + str(spam_count))
                # else:
                #     print("[-] Couldn't find Spam Count in - (DataBase 2):")
                big_spammer = response_json.get('big_spammer', '')
                if big_spammer:
                    print("[+] Found if Big Spammer (DataBase 2): " + str(big_spammer))
                # else:
                #     print("[-] Couldn't if Big Spammer in - (DataBase 2):")

                networks = response_json.get('networks', [])
                if isinstance(networks, list) and networks:
                    network = networks[0]  # Get the first network
                    networks_firstname = network.get('first_name', '')
                    if networks_firstname:
                        print("[+] Found networks first name (DataBase 2): " + networks_firstname)

                    networks_lastname = network.get('last_name', '')
                    if networks_lastname:
                        print("[+] Found networks last name (DataBase 2): " + networks_lastname)
                    
                    networks_picture = network.get('thumbnail', '')
                    if networks_picture:
                        print("[+] Found networks picture (DataBase 2): " + networks_picture)
                    
                    networks_sn_id = network.get('sn_id', '')
                    if networks_sn_id:
                        print("[+] Found networks sn_id (DataBase 2): " + networks_sn_id + "\n")
                # else:
                #     print("[-] Couldn't find networks_sn_id in - (DataBase 2):")

        else:
            print("Unexpected response format from DataBase 2")


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
                        print("\n[*] Checking in (DataBase 1): " + name)
                        if name:
                            print("\n[+] Found Name (DataBase 1): " + name)
                        # else:
                        #     print("[-] Couldn't find Name in - (DataBase 1):")
                        if picture:
                            print("[+] Found Picture (DataBase 1): " + picture)
                        # else:
                        #     print("[-] Couldn't find Picture in - (DataBase 1):")
                        if location:
                            print("[+] Found Location (DataBase 1): " + location)
                        # else:
                        #     print("[-] Couldn't find Location in - (DataBase 1):")
                        if address:
                            print("[+] Found Address (DataBase 1): " + address)
                        # else:
                        #     print("[-] Couldn't find Address in - (DataBase 1):")
                        if report_count:
                            print("[+] Found Report Count (DataBase 1): " + str(report_count))
                        # else:
                        #     print("[-] Couldn't find Report Count in - (DataBase 1):")
                        if old_tel_number:
                            print("[+] Found Old Phone Number (DataBase 1): " + str(old_tel_number))

                        if type_num:
                            print("[+] Found the Type of the Number (DataBase 1): " + type_num)
                        # else:
                        #     print("[-] Couldn't find Old Phone Number in - (DataBase 1):\n")

                    
                    # print("\nCaller ID Response:")
                    # print(json.dumps(json_object, indent=4) + "\n")
                except json.JSONDecodeError:
                    print("Failed to parse the response as JSON.")
                    # print(f"Raw response: {final_result}")
            else:
                print("Failed to decode the base64 string in decode_l.")

        else:
            print("Failed to decode the string in decode_a.")



    

            
    


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
        input_exit = input("[*] Do you want to continue? (y/n):")
        if input_exit.lower() in ["y", "Y", "yes", "Yes", "YES"]:
            return False
        else:
            return True
    def check_more():
        input_exit = input("\n[*] Do you want more informations? (y/n):")
        if input_exit.lower() in ["y", "Y", "yes", "Yes", "YES"]:
            return True
        else:
            return False
    
    def start(self):
        exit_rn = False
        syncme = Sync_Me()
        callerid = CallerID()
        
        
        print("\n[*] Menu:\n")
        print("     [1] Phone Number Checker")
        print("     [2] Help")
        print("     [3] Exit")
        input_select = input("\n[*] Select Option: ")
        if input_select.lower() in ["1"]:
            phone_number = input("[*] Enter Phone Number: ")
            callerid.start_callerid_check(phone_number, False)
            syncme.start_styncme(phone_number, False)
            more_ = Menu.check_more()
            if more_:
                syncme.start_styncme(phone_number, True)
                callerid.start_callerid_check(phone_number, True)
            exit_ = Menu.check_exit()
            if exit_:
                exit_rn = True
        if input_select.lower() in ["2"]:
            print("\nPhone Number Format Example: (IL: 972501111111), (US: 11234567890), etc...\n\nRead Me:\n[*] Phone Number Checker Detials:\n\nPhone Number Checker is an Dox tool that will show you some information about the phone number.\nfor example: name, location, picture, address, if hes a spammer and more...\nUse At Your Own Risk!!! Enjoy!\n")
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
