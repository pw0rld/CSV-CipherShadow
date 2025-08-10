/*
 * sme_test.c
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/dma-buf.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>

#define SUCCESS 0
#define DRIVERNAME "sme_test"
#define DUMP_SIZE 256 // 用于print_hex_dump的长度

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SME DECRYPT/ENCRYPT TEST");

// 虚拟地址转物理地址
static unsigned long vaddr2paddr(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d)) {
        printk("not mapped in p4d\n");
        return -1;
    }
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }

    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;

    return paddr;
}

// 初始化模块
int sme_test_init_module(void)
{
    unsigned char temp[16];
    unsigned char decrypt[16];
    int i = 0;
    void *enc;
    void *unenc;
    int error;
    struct page *page_1;
    uintptr_t result;
    struct h_node *cur;

    for (i = 0; i < 1; i++) {
        page_1 = alloc_page(GFP_KERNEL);
        enc = vmap(&page_1, 1, 0, PAGE_KERNEL_NOCACHE);               // C-bit
        unenc = vmap(&page_1, 1, 0, __pgprot(__PAGE_KERNEL_NOCACHE)); // no C-bit
        memset(unenc, 0xab, PAGE_SIZE);
        memset(enc, 0xab, PAGE_SIZE);
        flush_cache_all();
        printk("phsy address %llx %x", vaddr2paddr(unenc), vaddr2paddr(unenc));
        printk("phsy address %llx", vaddr2paddr(&unenc[0]));
        printk("phsy address %llx", vaddr2paddr(&unenc[128]));
        print_hex_dump(KERN_DEBUG, "[Current Value] ", DUMP_PREFIX_OFFSET, 16, 1, unenc, DUMP_SIZE, 1);
        memset(unenc, 0xac, PAGE_SIZE);
        memset(enc, 0xac, PAGE_SIZE);
        flush_cache_all();
        printk("\n\n");
        print_hex_dump(KERN_DEBUG, "[Second Value] ", DUMP_PREFIX_OFFSET, 16, 1, unenc, DUMP_SIZE, 1);
    }

    return SUCCESS;
}

// 退出模块
void sme_test_exit_module(void)
{
    // 空实现，如需清理资源可在此添加
}

module_init(sme_test_init_module);
module_exit(sme_test_exit_module);