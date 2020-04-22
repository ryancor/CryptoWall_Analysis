import sys
import gmpy2
from hash_pub_key import GetHashFromPubKey, GetHashFromEncryptedFile
from Crypto.Cipher import AES


def main():
    if len(sys.argv) < 2:
        print("[!] Usage: decrypt_file.py [enc_file]\n")
        exit(-1)

    enc_file = sys.argv[1]

    print("[+] Decrypting file")
    hash_header = bytes.fromhex(GetHashFromEncryptedFile(enc_file))
    print("[+] Found hash header => {}".format(hash_header.hex()))

    enc_data = open(enc_file, 'rb').read()
    enc_data_hash = enc_data[0:16]
    enc_data_aes_encrypted_key = enc_data[16:272]
    enc_data_remainder = enc_data[272:]

    # Use decrypt_aes_key.exe to extract keys from encrypted file
    key = bytes.fromhex('40B4247954AF27637CE4F7FABFE1CCFC6CD55FC724CAA840F82848EA4800B320')
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(enc_data_remainder)
    print("[+] Plaintext from file: {}".format(plaintext))



if __name__ == "__main__":
    main()
