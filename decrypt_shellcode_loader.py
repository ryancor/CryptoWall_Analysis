import sys
import pefile
import base64
from capstone import *


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

    # len(b64_str) + (-0x9a8), size used at VirtualAlloc
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


def DecryptToShellCode(b64decoded_str, size_of):
    tmp_buffer = bytearray()
    for _ in range(size_of):
        tmp_buffer += bytes([0])

    keys = [0x65, 0x00, 0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x0A]
    n = 1
    idx = 0
    tmp_char_1 = 0
    tmp_char_2 = 0
    tmp_char_3 = 0

    for _ in range(size_of):
        tmp_buffer[idx] = b64decoded_str[idx]
        tmp_char_1 = (tmp_buffer[idx] - (keys[8] ^ n) & 0xff) # convert negative value into unsigned int
        tmp_char_2 = (tmp_char_1 - (keys[4] ^ n) & 0xff)
        tmp_char_3 = (tmp_char_2 - (keys[0] ^ n) & 0xff)
        tmp_buffer[idx] = tmp_char_3

        idx += 1
        n += 1

    return tmp_buffer


def printHexVal(arr, size):
    for i in range(size):
        if i % 16 == 0:
            print("")
        print("{} ".format(hex(arr[i])), end='')
    print("")


def saveDissassemblyFromBytes(shellcode, filename):
    file = open(filename, 'w')
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(shellcode, 0x1000):
        file.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
    file.close()


def saveShellcodeToBin(shellcode, filename):
    file = open(filename, 'wb')
    file.write(shellcode)
    file.close()


def main():
    if len(sys.argv) != 2:
        print("./decrypt_shellcode_loader.py -d[dump assembly]/-e[emulate shellcode]")
        exit(-1)

    output_filepath_ = "extractions/pe_process_injector_dump"
    output_filepath_ = output_filepath_ + ".asm" if sys.argv[1] == '-d' else output_filepath_ + ".bin"

    b64_str = GetEncryptedShellcode("cryptowall.bin", 0xa0, 0x1665c)
    if b64_str[0:2] == 'cy':
        print("\n[+] Successfully extracted encoded shellcode")

    b64_decoded = CustomBase64Decode(b64_str)
    if b64_decoded[0:2] == b'\x9b\xce':
        print("[+] Successfully decoded encrypted shellcode")
    #Verify the bytes match in the programs debugger
    printHexVal(b64_decoded, 64)

    decrypted_shellcode = DecryptToShellCode(b64_decoded, len(b64_decoded))
    if decrypted_shellcode[0:2] == b'\x55\x8b':
        print("\n\n[+] Successfully decrypted shellcode")
        printHexVal(decrypted_shellcode, 64)
        if sys.argv[1] == '-d':
            print("\n[+] Using Capstone to Disassemble shellcode to x86")
            saveDissassemblyFromBytes(decrypted_shellcode, output_filepath_)
            print("[+] Successfully saved assembly dump file to {}".format(output_filepath_))
        else:
            print("\n[+] Emulating shellcode from {}".format(output_filepath_))
            saveShellcodeToBin(decrypted_shellcode, output_filepath_)

            try:
                from EMU_Scripts.ShellcodeEMU_Qiling import test_windowssc_x86
            except Exception:
                print("[!] Install Qiling to use Emulator")
                exit(-1)

            test_windowssc_x86(output_filepath_)


if __name__ == '__main__':
    main()
