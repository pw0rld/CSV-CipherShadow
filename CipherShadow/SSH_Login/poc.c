#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/kvm.h>
#include <asm/kvm.h>
#include <sched.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

#ifndef KVM_COPY_16BYTE_GPA
#define KVM_PAGE_FAULT_CSV             _IO(KVMIO,   0x19)
#define KVM_COPY_16BYTE_GPA   _IOW(0xAE, 0x17, struct kvm_copy_16byte_gpa_param)
struct kvm_copy_16byte_gpa_param {
	__u64 dst_gpa;
	__u64 dst_gpa_1;
	__u64 dst_gpa_2;
	__u64 src_gpa;
};
#define KVM_GET_PFN_FEATURE_INFO  _IOWR(KVMIO, 0x18, struct kvm_pfn_feature_info)

struct kvm_pfn_feature_info {
	__u64 pfn;
};
#define KVM_SINGLE_STEP_PAGE  _IOWR(KVMIO, 0x1a, struct kvm_single_step_page)
struct kvm_single_step_page {
	__u64 dst_gpa;
    __u64 single_pic_interval;
};
#endif

uint64_t kernel_base_virt;
uint64_t kernel_base_phys;
uint64_t kernel_page_offset_virt;
uint64_t init_top_pgt_cr3;

uint64_t open_kvm_page_fault(int fd) {
    int result;
    printf("[+]opening kvm page fault, KVM_PAGE_FAULT_CSV 0x%x\n", KVM_PAGE_FAULT_CSV);
    result = ioctl(fd, KVM_PAGE_FAULT_CSV);
    printf("result: %d\n", result);
    return result;
}

int copy_16byte_gpa(int fd, uint64_t dst_gpa, uint64_t src_gpa, uint64_t dst_gpa_1, uint64_t dst_gpa_2) {
    struct kvm_copy_16byte_gpa_param param;
    param.dst_gpa = dst_gpa;
    param.src_gpa = src_gpa;
    param.dst_gpa_1 = dst_gpa_1;
    param.dst_gpa_2 = dst_gpa_2;
    printf("[+]KVM_COPY_16BYTE_GPA: dst_gpa=0x%llx src_gpa=0x%llx\n", dst_gpa, src_gpa);
    int ret = ioctl(fd, KVM_COPY_16BYTE_GPA, &param);
    printf("result: %d\n", ret);
    return ret;
}


int get_feature(int fd, uint64_t gpa) {
    struct kvm_pfn_feature_info param;
    param.pfn = gpa;
    int ret = ioctl(fd, KVM_GET_PFN_FEATURE_INFO, &param);
    printf("result: %d\n", ret);
    printf("pfn: %llx\n", param.pfn);
    return ret;
}


int single_step_page(int fd, uint64_t dst_gpa, uint64_t single_pic_interval) {
    struct kvm_single_step_page param;
    param.dst_gpa = dst_gpa;
    param.single_pic_interval = single_pic_interval;
    int ret = ioctl(fd, KVM_SINGLE_STEP_PAGE, &param);
    printf("result: %d\n", ret);
    return ret;
}

void print_help(const char *progname) {
    printf("Usage: %s <command> [arguments...]\n", progname);
    printf("Supported commands:\n");
    printf("  pagefault\n");
    printf("      Open KVM page fault interface.\n");
    printf("  getfeature <gpa>\n");
    printf("      Query the ciphertext feature of the specified GPA (Guest Physical Address).\n");
    printf("      Example: %s getfeature 0x12345678\n", progname);
    printf("  copy16 <src_gpa> <dst_gpa> <dst_gpa_1> <dst_gpa_2>\n");
    printf("      Copy 16 bytes from src_gpa to dst_gpa, dst_gpa_1, and dst_gpa_2.\n");
    printf("      Example: %s copy16 0x1000 0x2000 0x3000 0x4000\n", progname);
    printf("  single_step_page <dst_gpa> <single_pic_interval>\n");
    printf("      Perform single-step execution on the specified page.\n");
    printf("      Example: %s single_step_page 0x12345678 100\n", progname);
}

int main(int argc, char const *argv[])
{
    int fd;

    printf("[+]opening /dev/kvm\n");
    fd = open("/dev/kvm", O_RDWR);
    if (fd < 0) {
        printf("[-]Cannot open device file ... check permissions\n");
        return 1;
    }
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    if(strcmp(argv[1], "pagefault") == 0) {
        open_kvm_page_fault(fd);
    }
    else if (strcmp(argv[1], "getfeature") == 0) {
        if (argc != 3) {
            print_help(argv[0]);
            return 1;
        }
        uint64_t gpa = strtoull(argv[2], NULL, 0);
        get_feature(fd, gpa);
    }
    else if (strcmp(argv[1], "copy16") == 0) {
        if (argc != 6) {
            print_help(argv[0]);
            return 1;
        }
        uint64_t src_gpa = strtoull(argv[2], NULL, 0);
        uint64_t dst_gpa = strtoull(argv[3], NULL, 0);
        uint64_t dst_gpa_1 = strtoull(argv[4], NULL, 0);
        uint64_t dst_gpa_2 = strtoull(argv[5], NULL, 0);
        copy_16byte_gpa(fd, dst_gpa, src_gpa, dst_gpa_1, dst_gpa_2);
    } 
    else if (strcmp(argv[1], "single_step_page") == 0) {
        if (argc != 4) {
            print_help(argv[0]);
            return 1;
        }
        uint64_t dst_gpa = strtoull(argv[2], NULL, 0);
        uint64_t single_pic_interval = strtoull(argv[3], NULL, 0);
        single_step_page(fd, dst_gpa, single_pic_interval);
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        print_help(argv[0]);
        return 1;
    }

    close(fd);
    return 0;
}
