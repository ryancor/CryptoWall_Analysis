import sys
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def GetHashFromPubKey(filename):
    with open(filename, "rb") as pub_key_file_object:
        pub_key_file_data = pub_key_file_object.read()
        public_key = load_pem_public_key(
            pub_key_file_data,
            backend=default_backend()
        )
    b64data = b'\n'.join(pub_key_file_data.splitlines()[1:-1])
    decoded = base64.b64decode(b64data)

    key = hashlib.md5(decoded).hexdigest()
    return key


def GetHashFromEncryptedFile(filename):
    with open(filename, 'rb') as md5_hash:
        md5_hash_data = md5_hash.read()

    key = md5_hash_data[0:16]
    return key.hex()


def main():
    hash_from_pub_key = GetHashFromPubKey(sys.argv[1])
    hash_from_enc_file = GetHashFromEncryptedFile(sys.argv[2])
    print(hash_from_enc_file + " == " + hash_from_pub_key)
    assert(hash_from_pub_key == hash_from_enc_file)


if __name__ == '__main__':
    # python In_Progress/hash_pub_key.py extractions/pub_key_1.pem extractions/SIG.txt
    main()
