import argparse
import sys
import hashlib
import re
import os
import subprocess
from collections import Counter, defaultdict
import matplotlib.pyplot as plt

gpa_list = []

def get_page_md5(gpa):
    pattern = re.compile(r'kvm_amd: gpa (0x[0-9a-f]+), group (\d+), feature_sum = (\d+)')
    features = []
    # ./weepoc getfeature 0x000000010bca1000
    cmd = "sudo ./weepoc getfeature {}".format(gpa)
    os.system(cmd)
    with subprocess.Popen(['dmesg', '--follow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1) as process:
        try:
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                match = pattern.search(line)
                if match:
                    extracted_gpa = match.group(1)
                    if extracted_gpa != gpa:
                        print(f"gpa not match: {extracted_gpa} != {gpa}")
                        continue
                    group = int(match.group(2))
                    feature_sum = int(match.group(3))
                    features.append(feature_sum)
                    if len(features) >= 64:
                        process.terminate()
                        break
        except KeyboardInterrupt:
            print("User interrupted, exiting...")
            process.terminate()
    # Ensure the number of features is 64
    if len(features) < 64:
        features.extend([0] * (64 - len(features)))
    else:
        features = features[:64]
    # Calculate md5
    feature_bytes = ','.join(str(f) for f in features).encode('utf-8')
    md5sum = hashlib.md5(feature_bytes).hexdigest()
    with open("md5.txt", "a") as f:
        f.write(f'Page {gpa} Feature sequence MD5: {md5sum}\n')
    os.system("dmesg -c")
    return md5sum

def analyze_binary_cacheline_features(bin_path, page_size=4096):
    page_md5s = []
    with open(bin_path, 'rb') as f:
        data = f.read()
    num_pages = len(data) // page_size
    for page_idx in range(num_pages):
        page = data[page_idx*page_size:(page_idx+1)*page_size]
        num_groups = page_size // 64
        features = []
        for group_idx in range(num_groups):
            group = page[group_idx*64:(group_idx+1)*64]
            # 4个cacheline, each 16 bytes
            cachelines = [group[i*16:(i+1)*16] for i in range(4)]
            feature_sum = 0
            for i in range(4):
                for j in range(i+1, 4):
                    if cachelines[i] == cachelines[j]:
                        feature_sum += (i+1) + (j+1)
            features.append(feature_sum)
            # print(f'Page {page_idx}, Group {group_idx}, Feature = {feature_sum}')
        # Calculate the md5 of each page
        feature_bytes = ','.join(str(f) for f in features).encode('utf-8')
        md5sum = hashlib.md5(feature_bytes).hexdigest()
        page_md5s.append(md5sum)
        print(f'Page {page_idx} Feature sequence MD5: {md5sum}')
    return page_md5s

def find_equal_blocks(blocks):
    """
    Input: blocks - a list of length 4, each element is a block content
    Output: a list, each element is a list of indices, representing the indices of blocks with the same content (only output the content with duplicates)
    """
    from collections import defaultdict
    content_to_indices = defaultdict(list)
    for idx, block in enumerate(blocks):
        content_to_indices[block].append(idx)
    # Only keep the content with duplicates
    result = [indices for indices in content_to_indices.values() if len(indices) > 1]
    return result

def encode_block_grouping(blocks):
    """
    Input: blocks - a list of length 4, each element is a block content
    Output: a unique number (0~14), representing the grouping of 4 blocks
    """
    # Group first
    groups = []
    used = [False]*4
    for i in range(4):
        if not used[i]:
            group = [i]
            used[i] = True
            for j in range(i+1, 4):
                if not used[j] and blocks[j] == blocks[i]:
                    group.append(j)
                    used[j] = True
            groups.append(tuple(group))
    # Sort, ensure the same grouping order
    groups = tuple(sorted(groups))
    # Enumerate all 15 grouping cases, build a lookup table
    grouping_table = [
        ((0,), (1,), (2,), (3,)),
        ((0, 1), (2,), (3,)),
        ((0, 2), (1,), (3,)),
        ((0, 3), (1,), (2,)),
        ((1, 2), (0,), (3,)),
        ((1, 3), (0,), (2,)),
        ((2, 3), (0,), (1,)),
        ((0, 1, 2), (3,)),
        ((0, 1, 3), (2,)),
        ((0, 2, 3), (1,)),
        ((1, 2, 3), (0,)),
        ((0, 1), (2, 3)),
        ((0, 2), (1, 3)),
        ((0, 3), (1, 2)),
        ((0, 1, 2, 3),),
    ]
    for idx, g in enumerate(grouping_table):
        if groups == g:
            return idx
    return -1

def analyze_all_pages(bin_path, page_size=4096):
    """
    Analyze all pages of a binary file, return the list of feature MD5s.
    :param bin_path: the path of the binary file
    :param page_size: the size of the page, default 4096 bytes
    :return: the list of feature MD5s
    """
    page_md5s = []
    # Store the offset of each feature value
    feature_offsets = defaultdict(list)
    
    with open(bin_path, 'rb') as f:
        data = f.read()
    num_pages = len(data) // page_size
    for page_idx in range(num_pages):
        page = data[page_idx*page_size:(page_idx+1)*page_size]
        num_groups = page_size // 64
        features = []
        for group_idx in range(num_groups):
            group = page[group_idx*64:(group_idx+1)*64]
            # 4个cacheline, each 16 bytes
            cachelines = [group[i*16:(i+1)*16] for i in range(4)]
            # Check if there are duplicate blocks
            equal_blocks = find_equal_blocks(cachelines)
            feature_id = encode_block_grouping(cachelines)
            if equal_blocks:  # If there are duplicate blocks
                # Calculate the actual offset in the program
                program_offset = page_idx * page_size + group_idx * 64
                feature_offsets[feature_id].append(program_offset)
            features.append(str(feature_id))
        # Calculate the md5 of each page
        feature_bytes = ','.join(features).encode('utf-8')
        md5sum = hashlib.md5(feature_bytes).hexdigest()
        page_md5s.append(md5sum)
    
    # Print the offset of each feature value
    print("\nFeature value corresponding to program offset:")
    for feature_id, offsets in sorted(feature_offsets.items()):
        if offsets:  # Only print the feature value with duplicate blocks
            print(f"\nFeature {feature_id}:")
            for offset in offsets:
                print(f"   Offset: 0x{offset:x}")
    
    return page_md5s

def analyze_all_pages_with_duplicates(bin_path, page_size=4096):
    """
    Analyze all pages of a binary file, return the list of feature MD5s, and count the number of duplicate MD5s.
    """
    page_md5s = analyze_all_pages(bin_path, page_size)
    md5_counter = Counter(page_md5s)
    total_pages = len(page_md5s)
    unique_md5s = len(md5_counter)
    duplicate_md5s = {md5: count for md5, count in md5_counter.items() if count > 1}
    print(f"Total pages: {total_pages}")
    print(f"Unique MD5s: {unique_md5s}")
    print(f"Duplicate MD5s: {len(duplicate_md5s)}")
    for md5, count in duplicate_md5s.items():
        print(f"MD5: {md5} appears {count} times")
    return page_md5s, duplicate_md5s

def compare_binaries_common_md5(bin_path1, bin_path2, page_size=4096):
    """
    Compare the page feature MD5s of two binary files, return the number of same MD5s and the list of same MD5s.
    :param bin_path1: the path of the first binary file
    :param bin_path2: the path of the second binary file
    :param page_size: the size of the page
    :return: (the number of same MD5s, the list of same MD5s)
    """
    md5s1 = set(analyze_all_pages(bin_path1, page_size))
    md5s2 = set(analyze_all_pages(bin_path2, page_size))
    common_md5s = md5s1 & md5s2
    print(f"The number of same page feature MD5s between two programs: {len(common_md5s)}")
    for md5 in common_md5s:
        print(f"Same MD5: {md5}")
    return len(common_md5s), list(common_md5s)

def analyze_multi_programs_md5_stats(bin_paths, page_size=4096):
    """
    Analyze the page MD5 fingerprint of multiple binary programs and analyze the distribution of duplicate pages.
    """
    all_md5s = []
    for path in bin_paths:
        md5s = analyze_all_pages(path, page_size)
        all_md5s.append(md5s)

    results = []
    for idx, md5s in enumerate(all_md5s):
        prog_name = bin_paths[idx]
        counter = Counter(md5s)
        pages = len(md5s)
        unique = sum(1 for v in counter.values() if v == 1)
        repeated = pages - unique
        zero_count = sum(1 for md5 in md5s if md5 == "d5e32f25aab24e5539677c702d94c575")
        # the unique page set of the current program
        unique_md5_set = set(md5 for md5, count in counter.items() if count == 1)

        # count the number of unique pages in each other program
        unique_in_others = {}
        for j, other_md5s in enumerate(all_md5s):
            if j == idx:
                continue
            other_name = bin_paths[j]
            other_set = set(other_md5s)
            count = len(unique_md5_set & other_set) # get the intersection
            unique_in_other_count = len(unique_md5_set) - count # the number of unique pages in the current program in other programs
            ratio = unique_in_other_count / pages if pages else 0
            unique_in_others[f"UniqueIn_{os.path.basename(other_name)}_Count"] = count
            unique_in_others[f"UniqueIn_{os.path.basename(other_name)}_Ratio"] = f"{ratio*100:.2f}%"



        result = {
            "Program": prog_name,
            "Pages": pages,
            "Unique": unique / pages,
            "UniqueInOthers": unique_in_others,
            "ZeroCount": zero_count
        }
        results.append(result)

    return results



# Example usage
if __name__ == "__main__":
    bin_paths = [
        "/home/pw0rld/security-25/sshd",
        "/usr/sbin/nginx",
        "/usr/bin/mysql",
        "/usr/bin/qemu-system-x86_64"
    ]
    stats = analyze_multi_programs_md5_stats(bin_paths)
    for stat in stats:
        print(stat)
