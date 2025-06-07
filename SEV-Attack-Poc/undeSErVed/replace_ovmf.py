import sys
import os

def swap_ovmf_blocks(filename, offset1, offset2, block_size=16):
    # check if the file exists
    if not os.path.isfile(filename):
        print(f"File not found: {filename}")
        sys.exit(1)

    with open(filename, 'r+b') as f:
        # read the first block
        f.seek(offset1)
        block1 = f.read(block_size)
        if len(block1) != block_size:
            print(f"Failed to read {block_size} bytes at offset {hex(offset1)}")
            sys.exit(1)

        # read the second block
        f.seek(offset2)
        block2 = f.read(block_size)
        if len(block2) != block_size:
            print(f"Failed to read {block_size} bytes at offset {hex(offset2)}")
            sys.exit(1)

        # write the second block to the first position
        f.seek(offset1)
        f.write(block2)

        # write the first block to the second position
        f.seek(offset2)
        f.write(block1)

    print(f"Swapped {block_size} bytes between offsets {hex(offset1)} and {hex(offset2)} in {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <ovmf_file> <offset1(hex)> <offset2(hex)>")
        print(f"Example: python3 {sys.argv[0]} OVMF.fd 0x003706D0 0x00a5150")
        sys.exit(1)

    ovmf_file = sys.argv[1]
    offset1 = int(sys.argv[2], 16)
    offset2 = int(sys.argv[3], 16)

    swap_ovmf_blocks(ovmf_file, offset1, offset2)
    # python3 replace_ovmf.py OVMF.fd 0x003706D0 0x00a5150
    # The offset address needs to be mapped to the kernel, the kernel is 0x003706D0, 0x00a5150