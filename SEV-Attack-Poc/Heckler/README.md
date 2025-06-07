# Heckler

Heckler is a security attack that exploits the hypervisor's control over interrupts in Confidential VMs (CVMs). By manipulating interrupt handlers, the untrusted hypervisor can alter register states and control flow within protected VMs, compromising their security despite the protection mechanisms of AMD SEV-SNP.


## Our test method

We manipulate the kernel to inject interrupt 0x00 into the victim, then observe the victim's execution behavior. If the vulnerability exists, the target victim will trigger an exception.

## important code
```
 
+    if(atomic_read(&user_data_npf_ex.user_interrupt_pending) == 1){
+		atomic_set(&user_data_npf_ex.user_interrupt_pending, 0);
+		printk("reset user_interrupt_pending finish");
+
+
+        svm->vmcb->control.event_inj = 0x80 | SVM_EVTINJ_VALID | SVM_EVTINJ_VALID_ERR | SVM_EVTINJ_TYPE_EXEPT;
+
+        printk("before run: event_inj %x\n",svm->vmcb->control.event_inj);
+        printk("before run: event_inj_err %x\n",svm->vmcb->control.event_inj_err);
+    }```
