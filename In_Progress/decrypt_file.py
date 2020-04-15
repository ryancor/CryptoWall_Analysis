import sys
import gmpy2
from hash_pub_key import GetHashFromPubKey, GetHashFromEncryptedFile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    # d is private exponent, n is the private modulus
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


def int_to_bytes(i):
	i = int(i)
	return i.to_bytes((i.bit_length()+7)//8, byteorder="big")


def bytes_to_int(b):
	return int.from_bytes(b, byteorder="big")


def main():
    if len(sys.argv) < 3:
        print("[!] Usage: decrypt_file.py [enc_file] [priv_key]\n")
        exit(-1)

    enc_file = sys.argv[1]
    priv_key = sys.argv[2]

    if len(sys.argv) == 4:
        if not priv_key.endswith('.pem') and not sys.argv[3].endswith('.pem'):
            print("[!] Usage: decrypt_file.py [enc_file] [priv_key] [pub_key]\n")
        else:
            print("[+] Decrypting file with public key")
    else:
        print("[+] Decrypting file without public key")
        hash_header = bytes.fromhex(GetHashFromEncryptedFile(enc_file))
        print("[+] Found hash header => {}".format(hash_header.hex()))

        with open(priv_key, "rb") as private_key_file_object:
            private_key = serialization.load_pem_private_key(
                private_key_file_object.read(),
                backend=default_backend(),
                password = None
            )

        enc_data = open(enc_file, 'rb').read()[16:]

        # f = open(priv_key,'r')
        # r = RSA.importKey(f.read())
        # decryptor = PKCS1_OAEP.new(r)
        # decrypted = decryptor.decrypt(enc_data)
        # print(decrypted)

        cipher_as_int = bytes_to_int(enc_data)
        message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
        message = int_to_bytes(message_as_int)

        print("Plaintext: {}\n".format(message))


    return


if __name__ == "__main__":
    main()
