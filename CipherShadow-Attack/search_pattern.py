#!/usr/bin/env python3
import re
import sys

def search_hex_pattern(filename):
    """
    Search for the pattern: 0x1 0x80 0x40 0x10 0x8 0x4 0x4 0x8 0x10 0x40 0x80 0x1
    with 0x0 allowed between values, but no other values allowed.
    """
    
    # Define the target pattern
    target_pattern = [0x1, 0x80, 0x40, 0x10, 0x8, 0x4, 0x4, 0x8, 0x10, 0x40, 0x80, 0x1]
    
    # Regex pattern to match hex values in dmesg format
    hex_pattern = r'0x[0-9a-fA-F]+'
    timestamp_pattern = r'\[([^\]]+)\]'
    
    try:
        with open(filename, 'r') as file:
            content = file.read()
            
        # Find all hex values in the file
        hex_matches = re.findall(hex_pattern, content)
        
        # Convert hex strings to integers
        hex_values = [int(x, 16) for x in hex_matches]
        
        print(f"Found {len(hex_values)} hex values in {filename}")
        print("Searching for pattern...")
        
        # Search for the pattern
        pattern_found = False
        for i in range(len(hex_values) - len(target_pattern) + 1):
            match = True
            pattern_pos = 0
            current_pos = i
            
            while pattern_pos < len(target_pattern) and current_pos < len(hex_values):
                if hex_values[current_pos] == target_pattern[pattern_pos]:
                    pattern_pos += 1
                    current_pos += 1
                elif hex_values[current_pos] == 0x0:
                    # Skip 0x0 values
                    current_pos += 1
                else:
                    # Found a non-zero value that doesn't match
                    match = False
                    break
            
            if match and pattern_pos == len(target_pattern):
                pattern_found = True
                print(f"\nPattern found starting at position {i}")
                
                # Find the line number, timestamp and context
                lines = content.split('\n')
                current_pos = 0
                for line_num, line in enumerate(lines, 1):
                    line_hex_count = len(re.findall(hex_pattern, line))
                    if current_pos <= i < current_pos + line_hex_count:
                        # Extract timestamp
                        timestamp_match = re.search(timestamp_pattern, line)
                        timestamp = timestamp_match.group(1) if timestamp_match else "No timestamp"
                        print(f"Line {line_num} [{timestamp}]: {line.strip()}")
                        break
                    current_pos += line_hex_count
                
                # Show the actual values found with timestamps
                print(f"Values found:")
                actual_values = []
                pos = i
                pattern_idx = 0
                
                while pattern_idx < len(target_pattern) and pos < len(hex_values):
                    # Find the line containing this hex value
                    current_pos = 0
                    for line_num, line in enumerate(lines, 1):
                        line_hex_count = len(re.findall(hex_pattern, line))
                        if current_pos <= pos < current_pos + line_hex_count:
                            timestamp_match = re.search(timestamp_pattern, line)
                            timestamp = timestamp_match.group(1) if timestamp_match else "No timestamp"
                            
                            if hex_values[pos] == target_pattern[pattern_idx]:
                                actual_values.append(f"Position {pos} [{timestamp}]: 0x{hex_values[pos]:x}")
                                pattern_idx += 1
                            elif hex_values[pos] == 0x0:
                                actual_values.append(f"Position {pos} [{timestamp}]: 0x{hex_values[pos]:x} (skipped)")
                            else:
                                actual_values.append(f"Position {pos} [{timestamp}]: 0x{hex_values[pos]:x} (mismatch)")
                            break
                        current_pos += line_hex_count
                    
                    pos += 1
                    if pattern_idx >= len(target_pattern):
                        break
                
                for val in actual_values:
                    print(f"  {val}")
                print()
        
        if not pattern_found:
            print("Pattern not found in the file.")
            
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"Error reading file: {e}")

def search_with_flexible_spacing(filename):
    """
    Alternative approach: search for the pattern with flexible spacing using regex
    """
    print("\n=== Alternative search with regex ===")
    
    # Create regex pattern that allows 0x0 between target values
    pattern_parts = []
    target_values = [0x1, 0x80, 0x40, 0x10, 0x8, 0x4, 0x4, 0x8, 0x10, 0x40, 0x80, 0x1]
    
    for i, val in enumerate(target_values):
        if i > 0:
            # Allow 0x0 between values
            pattern_parts.append(r'(?:0x0\s*)*')
        pattern_parts.append(f'0x{val:x}')
    
    regex_pattern = r''.join(pattern_parts)
    
    try:
        with open(filename, 'r') as file:
            for line_num, line in enumerate(file, 1):
                if re.search(regex_pattern, line, re.IGNORECASE):
                    print(f"Match found on line {line_num}: {line.strip()}")
                    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    filename = "dmesg.log"
    
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    
    print(f"Searching for hex pattern in {filename}")
    print("Target pattern: 0x1 0x80 0x40 0x10 0x8 0x4 0x4 0x8 0x10 0x40 0x80 0x1")
    print("(0x0 values allowed between pattern elements)")
    
    search_hex_pattern(filename)
    search_with_flexible_spacing(filename) 