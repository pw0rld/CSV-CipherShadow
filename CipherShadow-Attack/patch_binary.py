#!/usr/bin/env python3
import sys
import os
import subprocess

def get_file_offset(bin_path, vaddr):
    """
    Convert virtual address to file offset using objdump
    """
    cmd = f"objdump -h {bin_path}"
    try:
        # Use PIPE instead of capture_output for compatibility
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode != 0:
            print(f"Error running objdump: {result.stderr}")
            return None

        print("Section information:")
        found_section = False
        for line in result.stdout.split('\n'):
            if line.strip() and not line.startswith('Idx'):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        section_name = parts[0]
                        vma = int(parts[3], 16)  # Virtual address
                        offset = int(parts[5], 16)  # File offset
                        print(f"Section: {section_name}, VMA: 0x{vma:x}, Offset: 0x{offset:x}")
                        
                        # Check if vaddr is in this section
                        if vaddr >= vma:
                            # Get section size from the next line
                            size_line = next((l for l in result.stdout.split('\n') if l.strip() and l.split()[0] == section_name), None)
                            if size_line:
                                size = int(size_line.split()[2], 16)
                                if vaddr < vma + size:
                                    found_section = True
                                    print(f"Found matching section: {section_name}")
                                    # Calculate the correct offset
                                    file_offset = offset + (vaddr - vma)
                                    print(f"Calculated file offset: 0x{file_offset:x}")
                                    return file_offset
                    except (ValueError, IndexError) as e:
                        continue

        if not found_section:
            print(f"Could not find section containing address 0x{vaddr:x}")
        return None
    except Exception as e:
        print(f"Error getting file offset: {e}")
        return None

def bytes_to_hex(b):
    return ' '.join(f'{x:02x}' for x in b)

def get_patch_code(bin_path, target_addr):
    """
    Get the appropriate patch code based on the original instruction length
    """
    # Default patch code
    patch_code = bytes.fromhex('48 31 c0 c3')  # xor rax, rax + ret
    
    # Get the original instruction length
    cmd = f"objdump -d {bin_path} --start-address={target_addr} --stop-address={hex(int(target_addr, 16) + 16)}"
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if target_addr in line:
                    # Extract the instruction bytes
                    parts = line.split(':')[1].strip().split()
                    if parts:
                        # Get the length of the first instruction
                        instr_len = len(parts[0].split())
                        print(f"Original instruction length: {instr_len} bytes")
                        # Create patch code of the same length
                        if instr_len == 6:  # jmpq instruction
                            patch_code = bytes.fromhex('48 31 c0 c3 90 90')  # xor rax, rax + ret + 2 nops
                        elif instr_len == 5:  # pushq instruction
                            patch_code = bytes.fromhex('48 31 c0 c3 90')  # xor rax, rax + ret + 1 nop
                        else:
                            print(f"Warning: Unknown instruction length {instr_len}, using default patch")
                        break
    except Exception as e:
        print(f"Error getting instruction length: {e}")
    
    return patch_code

def patch_binary(bin_path, target_addr, output_path=None):
    """
    Patch binary file at specified address with code to clear rax register
    Args:
        bin_path: Path to the binary file
        target_addr: Target address to patch (hex string from objdump)
        output_path: Optional output path for the patched binary
    """
    # Get the patch code first
    patch_code = get_patch_code(bin_path, target_addr)
    
    # Convert virtual address to file offset
    vaddr = int(target_addr, 16)
    print(f"\nTrying to convert virtual address 0x{vaddr:x} to file offset...")
    
    # Get file offset
    file_offset = get_file_offset(bin_path, vaddr)
    
    if file_offset is None:
        print(f"Error: Could not convert virtual address 0x{vaddr:x} to file offset")
        return False
    
    # Read the binary file
    with open(bin_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Check if offset is valid
    if file_offset + len(patch_code) > len(data):
        print(f"Error: File offset 0x{file_offset:x} + {len(patch_code)} bytes exceeds file size")
        return False
    
    # Show original content
    original_content = data[file_offset:file_offset+len(patch_code)]
    print("\nOriginal content:")
    print(f"Offset 0x{file_offset:x}: {bytes_to_hex(original_content)}")
    
    # Apply the patch
    data[file_offset:file_offset+len(patch_code)] = patch_code
    
    # Show patched content
    print("\nPatched content:")
    print(f"Offset 0x{file_offset:x}: {bytes_to_hex(patch_code)}")
    
    # Determine output path
    if output_path is None:
        base, ext = os.path.splitext(bin_path)
        output_path = f"{base}_patched{ext}"
    
    # Write the patched binary
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"\nSuccessfully patched binary at virtual address 0x{vaddr:x} (file offset: 0x{file_offset:x})")
    print(f"Patched binary saved to: {output_path}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python patch_binary.py <binary_path> <target_address> [output_path]")
        print("Example: python patch_binary.py ./program 0x400680")
        sys.exit(1)
    
    bin_path = sys.argv[1]
    target_addr = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(bin_path):
        print(f"Error: Binary file {bin_path} does not exist")
        sys.exit(1)
    
    patch_binary(bin_path, target_addr, output_path) 