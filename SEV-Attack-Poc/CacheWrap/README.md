# CacheWrap

CacheWrap is a security attack that exploits the behavior of the INVD instruction in AMD SEV-SNP protected systems. The attack focuses on the Last Level Cache (LLC) management and its interaction with kernel data.

## How It Works
The attack leverages the INVD instruction's behavior of invalidating the cache without performing a write-back operation. When INVD is executed, it invalidates the LLC contents but doesn't write the data back to memory. This becomes particularly dangerous when the LLC contains kernel data, as the loss of this data can cause system crashes.

## Test Method
Our proof-of-concept (PoC) verifies this vulnerability by:
1. Executing INVD to invalidate the LLC
2. Observing system behavior when kernel data is present in the LLC
3. The test has two possible outcomes:
   - System crash (when kernel data is lost)
   - Successful execution (when no critical kernel data is affected)

