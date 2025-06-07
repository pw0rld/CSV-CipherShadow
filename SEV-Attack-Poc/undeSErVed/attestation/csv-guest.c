#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>


struct csv_guest_mem{
	unsigned long va;  //user space virtual address
	int size;
};

#define HASH_LEN 32

typedef struct _hash_block_u {
	unsigned char block[HASH_LEN];
} hash_block_u;

#define CSV_GUEST_IOC_TYPE     'D'
#define GET_ATTESTATION_REPORT  _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE 64
#define KVM_HC_VM_ATTESTATION	100	/* Specific to Hygon platform */

static int csv_guest_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO"csv_guest_open \n");
	return 0;
}
static int csv_guest_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
	long ret = 0;

	asm volatile("vmmcall"
		: "=a"(ret)
		: "a"(nr), "b"(p1), "c"(len)
		: "memory");
	return ret;
}


static long csv_guest_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	void __user* argp = (void __user*)arg;
	struct csv_guest_mem mem_para = {0};
	void *mem = NULL;

	if (copy_from_user(&mem_para, argp, sizeof(struct csv_guest_mem))) {
		pr_err("%s copy from user failed \n", __func__);
		ret = -EFAULT;
	}
	switch (cmd) {

		case GET_ATTESTATION_REPORT:

			mem = kzalloc(mem_para.size, GFP_KERNEL);
			if (!mem) {
				pr_err("%s kzalloc for size 0x%x failed\n", __func__, mem_para.size);
				return -ENOMEM;
			}

			/*cpoy user data and mnonce  to kernel buf*/
			if (copy_from_user(mem, (void __user*)(mem_para.va), GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE + sizeof(hash_block_u))) {
				pr_err("%s copy user data and mnonce from user failed \n", __func__);
				ret = -EFAULT;
				goto error;
			}

			printk("pa: %lx\n", __pa(mem));
			ret = hypercall(KVM_HC_VM_ATTESTATION, __pa(mem), mem_para.size);
			if (ret) {
				printk("hypercall fail: %d\n", ret);
				goto error;
			}

			if (copy_to_user((void __user*)(mem_para.va),mem,mem_para.size)){
				pr_err("%s copy mem to user failed \n", __func__);
				ret = -EFAULT;
				goto error;
			}

			if(mem){
				kfree(mem);
				mem = NULL;
			}
			break;
		default:
			printk("don't support this cmd = %d\n",cmd);
			return -EINVAL;
	}
	return ret;
error:
	if(mem){
		kfree(mem);
		mem = NULL;
	}
	return ret;
}

static struct file_operations csv_guest_fops = {
	.owner = THIS_MODULE,
	.open  = csv_guest_open,
	.unlocked_ioctl = csv_guest_ioctl,
	.compat_ioctl = csv_guest_ioctl,
	.release = csv_guest_release,

};

static struct miscdevice csv_guest_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "csv-guest",
	.fops = &csv_guest_fops,
	.mode = 0777,
};

static int __init csv_guest_init(void)
{
	int ret = -1;
	ret = misc_register(&csv_guest_dev);
	if(ret){
		printk(KERN_ERR"csv_guest_dev: cannot register misc device!\n");
		return ret;
	}
	printk(KERN_ALERT"Succedded to initialize csv_guest device.\n");
	return 0;
}

static void __exit csv_guest_exit(void)
{
	misc_deregister(&csv_guest_dev);
}

MODULE_LICENSE("GPL");
module_init(csv_guest_init);
module_exit(csv_guest_exit);
