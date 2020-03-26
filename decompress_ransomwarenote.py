# python2
import pefile
import array
import cStringIO
import logging
import struct


# The decompresion algorithm is from google/rekall repo
# https://github.com/google/rekall/rekall-core/rekall/plugins/filesystems/lznt1.py
def get_displacement(offset):
    """Calculate the displacement."""
    result = 0
    while offset >= 0x10:
        offset >>= 1
        result += 1

    return result


DISPLACEMENT_TABLE = array.array(
    'B', [get_displacement(x) for x in xrange(8192)])

COMPRESSED_MASK = 1 << 15
SIGNATURE_MASK = 3 << 12
SIZE_MASK = (1 << 12) - 1
TAG_MASKS = [(1 << i) for i in range(0, 8)]


def lznt1_decompress_data(cdata, logger=None):
    """Decompresses the data."""

    if not logger:
        lznt1_logger = logging.getLogger("ntfs.lznt1")
    else:
        lznt1_logger = logger.getChild("lznt1")
    # Change to DEBUG to turn on module level debugging.
    lznt1_logger.setLevel(logging.ERROR)
    in_fd = cStringIO.StringIO(cdata)
    output_fd = cStringIO.StringIO()
    block_end = 0

    while in_fd.tell() < len(cdata):
        block_offset = in_fd.tell()
        uncompressed_chunk_offset = output_fd.tell()

        block_header = struct.unpack("<H", in_fd.read(2))[0]
        lznt1_logger.debug("Header %#x @ %#x", block_header, block_offset)
        if block_header & SIGNATURE_MASK != SIGNATURE_MASK:
            lznt1_logger.debug("Signature does not match")
            break

        size = (block_header & SIZE_MASK)
        lznt1_logger.debug("Block size %s", size + 3)

        block_end = block_offset + size + 3

        if block_header & COMPRESSED_MASK:
            while in_fd.tell() < block_end:
                header = ord(in_fd.read(1))
                lznt1_logger.debug("Tag %#x", header)
                for mask in TAG_MASKS:
                    if in_fd.tell() >= block_end:
                        break

                    if header & mask:
                        pointer = struct.unpack("<H", in_fd.read(2))[0]
                        # had to mod the array since it was getting a ton of array indexes out of bounds
                        displacement = DISPLACEMENT_TABLE[(output_fd.tell() - uncompressed_chunk_offset - 1) % 8192]

                        symbol_offset = (pointer >> (12 - displacement)) + 1
                        symbol_length = (pointer & (0xFFF >> displacement)) + 3

                        output_fd.seek(-symbol_offset, 2)
                        data = output_fd.read(symbol_length)

                        # Pad the data to make it fit.
                        if 0 < len(data) < symbol_length:
                            data = data * (symbol_length / len(data) + 1)
                            data = data[:symbol_length]

                        output_fd.seek(0, 2)
                        lznt1_logger.debug(
                            "Wrote %s @ %s/%s: Phrase %s %s %x",
                            len(data), in_fd.tell(),
                            output_fd.tell(), symbol_length, symbol_offset,
                            pointer)

                        output_fd.write(data)

                    else:
                        data = in_fd.read(1)
                        lznt1_logger.debug("Symbol %#x", ord(data))
                        output_fd.write(data)

        else:
            # Block is not compressed
            data = in_fd.read(size + 1)
            output_fd.write(data)

    result = output_fd.getvalue()
    return result
# End of Rekall Code


def getRansomNote(filename, signature_location):
    pe = pefile.PE(filename)
    compressed_note = b''

    print("[!] Searching PE sections for .data")
    for section in pe.sections:
        if b".data" in section.Name:
            start = 0x1f90 + signature_location
            end = start + 0x52B8
            for byte in section.get_data()[start:end]:
                # compressed_note += byte.to_bytes(1, byteorder="big")
                compressed_note += byte

    lznt1_signature = struct.unpack("<H", compressed_note[0:2])[0]
    if lznt1_signature & SIGNATURE_MASK == SIGNATURE_MASK:
        print("[+] Found ransomware note")

        decompressed_note = lznt1_decompress_data(compressed_note)
        return decompressed_note
    else:
        print("[-] Could not find note with current offsets")
        exit(-1)
    pe.close()


def main():
    f = open("extractions/ransomware_note.html", "w")
    buffer = getRansomNote("cryptowall_055A0000.bin", 4)
    if buffer[0:22].find("<html>", 6):
        print("[+] Decompressed successfully")
    f.write(buffer)
    f.close()

    print("[+] Finished writing to file")


if __name__ == "__main__":
    main()
