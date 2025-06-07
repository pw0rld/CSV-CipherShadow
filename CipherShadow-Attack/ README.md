# CipherShadow-Attack flow

Our end-to-end attack flow targets the SSH service, assuming the SSH program is running inside the victim virtual machine. We repeatedly attempt to log in, and before each login, we clear the NX (No-eXecute) bit of certain pages to induce page faults. Each login attempt triggers a page fault; it is important to note that not only the SSH process, but also other system processes may trigger page faults. At this point, we collect the PFN (Page Frame Number) of these pages and extract their ciphertext features to compare with those of the SSHD process. If the target is not found, we use single-step execution to obtain register features, which helps us locate the offset to modify.


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