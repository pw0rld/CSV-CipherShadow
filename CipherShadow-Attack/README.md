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