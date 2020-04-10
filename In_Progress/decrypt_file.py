import gmpy2, os, sys, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
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
        print("[!] Usage: decrypt_file.py [pub_key] [encryped_file]")
        exit(-1)

    private_key_file_temp = sys.argv[1]
    encrypted_file = sys.argv[2]

    if not os.path.exists(private_key_file_temp) or not os.path.exists(encrypted_file):
        print("[-] File does not exist.")
        exit(-1)
    else:
        with open(private_key_file_temp, "rb") as private_key_file_object:
            private_key = serialization.load_pem_private_key(
                private_key_file_object.read(),
                backend=default_backend(),
                password = None
            )

    cipher_hex = open(encrypted_file, "rb").read()

    # f = open(private_key_file_temp,'r')
    # r = RSA.importKey(f.read())
    # decryptor = PKCS1_OAEP.new(r)
    # decrypted = decryptor.decrypt(cipher_hex)
    # print(decrypted)

    cipher_as_int = bytes_to_int(cipher_hex)
    message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
    message = int_to_bytes(message_as_int)

    print("Plaintext: {}\n".format(message))


if __name__ == "__main__":
    main()
