import pefile
import base64


# the resource section contains the 4th stage loader which injects a new PE file
# to a process memory
def GetEncryptedShellcode(filename, offset, size):
    pe = pefile.PE(filename)
    b64_bytes = ''

    print("[!] Searching PE sections for .rsrc")
    for section in pe.sections:
        if b".rsrc" in section.Name:
            start = offset
            end = start + size
            for byte in section.get_data()[start:end]:
                b64_bytes += chr(byte)
    return b64_bytes


def CustomBase64Decode(b64_str):
    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    buffer = b''
    next_char = 0
    i, y, n, z = 0, 0, 0, 0

    # len(b64_str) + (-0x9a8)
    for _ in range(0x15CB4):
        char = 1
        while(1):
            if ord(b64_str[y]) == ord(charset[z]):
                next_char = char - 1
                z = 0
                break
            z += 1
            char += 1
            if char == 0x41:
                break

        if next_char >= 0:
            n = next_char + (n << 6)
            i += 6
            if(i >= 8):
                i -= 8
                next_char = n >> i
                n %= 1 << i
                next_char %= 256
                buffer += bytes([next_char])

        y += 1
    return buffer


def DecryptToShellCode(b64decoded_str):
    # TODO
    return


def main():
    b64_str = GetEncryptedShellcode("cryptowall.bin", 0xa0, 0x1665c)
    if b64_str[0:2] == 'cy':
        print("\n[+] Successfully extracted encoded shellcode")

    b64_decoded = CustomBase64Decode(b64_str)
    if b64_decoded[0:2] == b'\x9b\xce':
        print("[+] Successfully decoded encrypted shellcode")

    # Verify the bytes match in the programs debugger
    for i in range(64):
        if i % 16 == 0:
            print("")
        print("{} ".format(hex(b64_decoded[i])), end='')


if __name__ == '__main__':
    main()
