import sys
from hash_pub_key import GetHashFromPubKey, GetHashFromEncryptedFile


def main():
    if len(sys.argv) < 2:
        print("[!] Usage: decrypt_file.py [enc_file]\n")
        exit(-1)

    if len(sys.argv) == 3:
        if not sys.argv[2].endswith('.pem'):
            print("[!] Usage: decrypt_file.py [enc_file] [pub_key]\n")
        else:
            print("[+] Decrypting file with public key")
    else:
        print("[+] Decrypting file without public key")

    return


if __name__ == "__main__":
    main()
