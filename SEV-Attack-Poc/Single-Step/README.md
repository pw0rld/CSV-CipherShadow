# Single-Step

Single-Step is mostly achieved through APIC injection, which then triggers an interrupt in the Guest. The challenging part is determining the timing of the injection, which is often combined with page faults.
In our testing, we inject the APIC timer in `__svm_sev_es_vcpu_run` within `svm_vcpu_enter_exit`, set the `apic_interval`, and observe the MSR registers to determine the number of instructions executed.

It's worth noting that if x2apic is enabled, you need to add 'nox2apic' to the kernel command line. This is because our injection method uses MMIO, and performing single-step on a machine with x2apic enabled will cause system crashes.