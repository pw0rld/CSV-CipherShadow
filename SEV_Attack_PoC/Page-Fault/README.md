# Page—Fault

Page fault attacks exploit the memory management mechanisms in SEV/CSV environments. The attack works by manipulating page table entries to trigger page faults when the guest VM accesses specific memory pages.

## Attack Methodology

1. **Page Table Manipulation**: Modify page table entries in the host to mark certain guest pages as non-present or invalid
2. **Fault Injection**: When the guest attempts to access these pages, a page fault is triggered
3. **Information Leakage**: The hypervisor can observe the fault patterns, memory access timing, and potentially infer sensitive information about guest execution
4. **Side Channel Analysis**: By analyzing the frequency and timing of page faults, attackers can deduce information about guest behavior and data

## Implementation Approach

The page fault attack can be implemented by:
- Intercepting guest page table operations
- Strategically invalidating page table entries
- Monitoring page fault handlers to gather timing information
- Correlating fault patterns with guest application behavior

This attack demonstrates that even with memory encryption, the memory management layer can still leak information about guest VM execution patterns.
