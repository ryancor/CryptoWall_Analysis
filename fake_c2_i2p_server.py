# py -m pip install flask pyopenssl pycryptodome
# Place in your /etc/hosts 127.0.0.1 proxy1-1-1.i2p
# Place in your /etc/hosts 127.0.0.1 proxy2-2-2.i2p
from flask import Flask, escape, request
from Crypto.Cipher import ARC4


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


# Path is always a random generated string, so we have to wildcard the route
@app.route('/<path:text>', methods=['GET', 'POST'])
def setup(text):
    print("Data Received from CryptoWall Binary:")
    print("-"*30)

    plaintext_key = ByteSwapURIPathString(text)
    rc4_data = dict(request.form)
    for val in rc4_data:
        ciphertext = rc4_data[val]

    print("[!] Found URI Header: {}".format(text))
    print("[+] Created key from URI: {}".format(plaintext_key))
    print("[!] Found ciphertext: {}".format(ciphertext))

    rc4_key = ARC4.new(plaintext_key.encode())
    plaintext = rc4_key.decrypt(bytes.fromhex(ciphertext))
    print("[+] Recovered plaintext: {}".format(plaintext))

    return "None", 200 # TODO: send back dict data with RSA pub key, RC4 encrypted


if __name__ == "__main__":
    # test function works by using an example string generated from cryptowall
    assert(ByteSwapURIPathString("tfuzxqh6wf7mng") == "67ffghmnqtuwxz")
    app.run(port=80)
