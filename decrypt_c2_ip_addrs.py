import pefile

RC4_Keylen = 256

def GetEncryptedBytes(filename, offset, size):
    pe = pefile.PE(filename)
    enc_arr = []

    print("[!] Searching PE sections for .data")
    for section in pe.sections:
        if b".data" in section.Name:
            start = offset
            end = start + size
            for byte in section.get_data()[start:end]:
                enc_arr.append(byte)
    return enc_arr


def GrabPlaintextPassword(string_buffer):
    password = string_buffer[4:13]
    return ''.join([chr(i) for i in password])


# Generate 256Byte Key from Plaintext Key
def RC4_KeySchedulingAlgorithm(plaintext_password):
    generated_buffer = b''

    tmp_buffer = bytearray()
    for i in range(RC4_Keylen):
        tmp_buffer += bytes([i])

    z = 0
    n = 0
    for j in range(RC4_Keylen):
        z = (z + ord(plaintext_password[n]) + (tmp_buffer[j])) % RC4_Keylen
        y = tmp_buffer[j]
        tmp_buffer[j] = tmp_buffer[z]
        tmp_buffer[z] = y
        n = (n + 1) % 9
    generated_buffer = tmp_buffer
    return generated_buffer


def RC4Decrypt(encrypted_arr, key_bytes):
    remaining_bytes = encrypted_arr[18:]
    result = ''

    n = 0
    y = 0
    for i in range(len(remaining_bytes)):
        n += 1
        y += key_bytes[n]
        z = key_bytes[n]
        key_bytes[n] = key_bytes[y%RC4_Keylen]
        key_bytes[y%RC4_Keylen] = z
        #print(hex(key_bytes[(key_bytes[y%256] + key_bytes[n]) % 256]), hex(remaining_bytes[i]))
        result += chr((key_bytes[(key_bytes[y%RC4_Keylen] + key_bytes[n]) % RC4_Keylen]) ^ remaining_bytes[i])

    return result


def main():
    encrypted_ip_data = GetEncryptedBytes("cryptowall_055A0000.bin", 0xB8, 0x89)
    if encrypted_ip_data[0] == 0x09:
        print("[+] Extracted encrypted data from PE File\n")

    password = GrabPlaintextPassword(encrypted_ip_data)
    print("[+] Got plaintext key: {}\n".format(password))

    key_bytes = RC4_KeySchedulingAlgorithm(password)
    print("[+] Generated key bytes from plaintext:\n{}\n".format(key_bytes))

    ip_addr = RC4Decrypt(encrypted_ip_data, key_bytes)
    print("Decrypted data:")
    for i in range(0, len(ip_addr), 24):
        print(ip_addr[i:i+24])


if __name__ == '__main__':
    main()
