#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/sm3.h"
#include "openssl/sha.h"

static int file_size(char* filename)
{
    struct stat statbuf;
    memset(&statbuf, 0, sizeof(statbuf));

    stat(filename, &statbuf);

    return statbuf.st_size;
}

/**
 * UUID_LE - converts the fields of UUID to little-endian array,
 * each of parameters is the filed of UUID.
 *
 * @time_low: The low field of the timestamp
 * @time_mid: The middle field of the timestamp
 * @time_hi_and_version: The high field of the timestamp
 *                       multiplexed with the version number
 * @clock_seq_hi_and_reserved: The high field of the clock
 *                             sequence multiplexed with the variant
 * @clock_seq_low: The low field of the clock sequence
 * @node0: The spatially unique node0 identifier
 * @node1: The spatially unique node1 identifier
 * @node2: The spatially unique node2 identifier
 * @node3: The spatially unique node3 identifier
 * @node4: The spatially unique node4 identifier
 * @node5: The spatially unique node5 identifier
 */
#define UUID_LE(time_low, time_mid, time_hi_and_version,                             \
                clock_seq_hi_and_reserved, clock_seq_low, node0, node1, node2,       \
                node3, node4, node5)                                                 \
    {                                                                                \
        (time_low) & 0xff, ((time_low) >> 8) & 0xff, ((time_low) >> 16) & 0xff,      \
        ((time_low) >> 24) & 0xff, (time_mid) & 0xff, ((time_mid) >> 8) & 0xff,      \
        (time_hi_and_version) & 0xff, ((time_hi_and_version) >> 8) & 0xff,           \
        (clock_seq_hi_and_reserved), (clock_seq_low), (node0), (node1), (node2),     \
        (node3), (node4), (node5)                                                    \
    }

#define ALIGN_UP(size, align) (((size) + (align)-1) & (~((align)-1)))

/* Version 4 UUID (pseudo random numbers), RFC4122 4.4. */
typedef struct {
    unsigned char data[16];
} QemuUUID;

/* hard code sha256 digest size */
#define HASH_SIZE 32
typedef struct __attribute__((packed)) CsvHashTableEntry {
    QemuUUID guid;
    uint16_t len;
    uint8_t hash[HASH_SIZE];
} CsvHashTableEntry;

typedef struct __attribute__((packed)) CsvHashTable {
    QemuUUID guid;
    uint16_t len;
    CsvHashTableEntry cmdline;
    CsvHashTableEntry initrd;
    CsvHashTableEntry kernel;
    uint8_t padding[];
} CsvHashTable;

static const QemuUUID csv_hash_table_header_guid = {
    UUID_LE(0x9438d606, 0x4f22, 0x4cc9, 0xb4, 0x79, 0xa7, 0x93,
                    0xd4, 0x11, 0xfd, 0x21)
};

static const QemuUUID csv_kernel_entry_guid = {
    UUID_LE(0x4de79437, 0xabd2, 0x427f, 0xb8, 0x35, 0xd5, 0xb1,
                    0x72, 0xd2, 0x04, 0x5b)
};
static const QemuUUID csv_initrd_entry_guid = {
    UUID_LE(0x44baf731, 0x3a2f, 0x4bd7, 0x9a, 0xf1, 0x41, 0xe2,
                    0x91, 0x69, 0x78, 0x1d)
};
static const QemuUUID csv_cmdline_entry_guid = {
    UUID_LE(0x97d02dd8, 0xbd20, 0x4c94, 0xaa, 0x78, 0xe7, 0x71,
                    0x4d, 0x36, 0xab, 0x2a)
};

static int sha256_hash(uint8_t* buf, size_t len, uint8_t *result)
{
    SHA256_CTX ctx;
    // Calculate the hash
    if (SHA256_Init(&ctx) != 1)
        return -1;

    if ((len > 0) && (buf != NULL) && (SHA256_Update(&ctx, buf, len) != 1))
        return -1;

    if (SHA256_Final((uint8_t*)result, &ctx) != 1)
        return -1;

    return 0;
}

static void csv_report_dump_part(const char* name, uint8_t *section, uint32_t len)
{
    printf("report.%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)section[i];
        printf("%02hhx", c);
    }
    printf("\n");
}

static int load_data_from_file(const char *path, void *buff,size_t len)
{
    if (!path || !*path) {
        printf("no file\n");
        return -ENOENT;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("open file %s fail %s\n", path, strerror(errno));
        return fd;
    }

    int rlen = 0, n;

    while (rlen < len) {
        n = read(fd, buff + rlen,len);
        if (n == -1) {
            printf("read file error\n");
            close(fd);
            return n;
        }
        if (!n) {
            break;
        }
        rlen += n;
    }

    close(fd);

    return 0;
}

static int fill_csv_hash_table(CsvHashTable *ht, char *kernel_file, off_t kernel_size,
                                char *initrd_file, off_t initrd_size,
                                char *cmdline_file, off_t cmdline_size)
{
    uint8_t cmdline_hash[HASH_SIZE] = {0};
    uint8_t initrd_hash[HASH_SIZE] = {0};
    uint8_t kernel_hash[HASH_SIZE] = {0};
    uint8_t *cmdline_buffer = NULL;
    uint8_t *initrd_buffer = NULL;
    uint8_t *kernel_buffer = NULL;
    int ret = 0;

    /*
     * Calculate hash of kernel command-line with the terminating null byte. If
     * the user doesn't supply a command-line via -append, the 1-byte "\0" will
     * be used.
     */
    if (cmdline_size <= 0) {
        cmdline_buffer = (uint8_t*)malloc(1);
        cmdline_size = 1;
        cmdline_buffer[0] = '\0';
    } else {
        cmdline_buffer = (uint8_t*)malloc(cmdline_size);
        ret = load_data_from_file(cmdline_file, cmdline_buffer, cmdline_size);
        if (ret) {
            printf("load cmdline from file fail\n");
            goto free_cmdline;
        }
        // file end with 0xa, but cmdline should be end with '\0'
        cmdline_buffer[cmdline_size-1] = 0x0;
    }

    ret = sha256_hash(cmdline_buffer, cmdline_size, cmdline_hash);
    if (ret) {
        printf("cmdline hash error");
        goto free_cmdline;
    }

    /*
     * Calculate hash of initrd. If the user doesn't supply an initrd via
     * -initrd, an empty buffer will be used (initrd_size == 0).
     */
    if (initrd_size > 0){
        initrd_buffer = (uint8_t*)malloc(initrd_size);
        ret = load_data_from_file(initrd_file, initrd_buffer, initrd_size);
        if (ret) {
            printf("load initrd from file fail\n");
            goto free_initrd;
        }
    }

    ret = sha256_hash(initrd_buffer, initrd_size, initrd_hash);
    if (ret) {
        printf("initrd hash error");
        goto free_initrd;
    }

    /* Calculate hash of the kernel */
    kernel_buffer = (uint8_t*)malloc(kernel_size);
    ret = load_data_from_file(kernel_file, kernel_buffer, kernel_size);
    if (ret) {
        printf("load kernel from file fail\n");
        goto free_kernel;
    }

    ret = sha256_hash(kernel_buffer, kernel_size, kernel_hash);
    if (ret) {
        printf("kernel hash error");
        goto free_kernel;
    }

    ht->guid = csv_hash_table_header_guid;
    ht->len = sizeof(*ht);

    ht->cmdline.guid = csv_cmdline_entry_guid;
    ht->cmdline.len = sizeof(ht->cmdline);
    memcpy(ht->cmdline.hash, cmdline_hash, sizeof(ht->cmdline.hash));

    ht->initrd.guid = csv_initrd_entry_guid;
    ht->initrd.len = sizeof(ht->initrd);
    memcpy(ht->initrd.hash, initrd_hash, sizeof(ht->initrd.hash));
    ht->kernel.guid = csv_kernel_entry_guid;
    ht->kernel.len = sizeof(ht->kernel);
    memcpy(ht->kernel.hash, kernel_hash, sizeof(ht->kernel.hash));

free_kernel:
    if (kernel_buffer)
        free(kernel_buffer);

free_initrd:
    if (initrd_buffer)
        free(initrd_buffer);

free_cmdline:
    free(cmdline_buffer);

    return ret;
}

int main(int argc,char *argv[])
{
    int ret                         = -1;
    off_t bios_size                 = 0;
    off_t kernel_size               = 0;
    off_t initrd_size               = 0;
    off_t cmdline_size              = 0;
    size_t hash_table_size_aligned  = 0;


    char *bios_file     = NULL;
    char *kernel_file   = NULL;
    char *initrd_file   = NULL;
    char *cmdline_file  = NULL;

    uint8_t *hash_buffer    = NULL;
    CsvHashTable *ht        = NULL;
    uint8_t digest[SM3_DIGEST_LENGTH];

    if(argc != 5){
        printf("Error:need 4 parameters\n");
        return -1;
    }
    printf("calc vm digest\n");

    bios_file = argv[1];
    bios_size = file_size(bios_file);
    if (bios_size <= 0) {
        printf("bios file not exist or size is zero\n");
        return ret;
    }
    printf("bios path is %s, size is %ld\n", bios_file, bios_size);

    kernel_file = argv[2];
    kernel_size = file_size(kernel_file);
    if (kernel_size <= 0) {
        printf("kernel file not exist or size is zero\n");
        return ret;
    }
    printf("kernel path is %s, size is %ld\n", kernel_file, kernel_size);

    initrd_file = argv[3];
    initrd_size = file_size(initrd_file);
    if (initrd_size <= 0){
        initrd_size = 0;
        printf("initrd file not exist or size is zero, use a null initrd to calc\n");
    } else
        printf("initrd path is %s, size is %ld\n", initrd_file, initrd_size);

    cmdline_file = argv[4];
    cmdline_size = file_size(cmdline_file);
    if (cmdline_size <= 0)
        printf("cmdline file not exist or size is zero, use a null cmdline to calc\n");
    else
        printf("cmdline path is %s, size is %ld\n", cmdline_file, cmdline_size);

    hash_table_size_aligned = ALIGN_UP(sizeof(CsvHashTable), 16);
    hash_buffer    = (uint8_t*)malloc(bios_size + hash_table_size_aligned);
    ret = load_data_from_file(bios_file, hash_buffer, bios_size);
    if (ret) {
        printf("load bios from file fail\n");
        goto free_hash;
    }

    ht = (CsvHashTable *)(hash_buffer+bios_size);

    ret = fill_csv_hash_table(ht, kernel_file, kernel_size, initrd_file, initrd_size,
                        cmdline_file, cmdline_size);
    if (ret) {
        printf("fill csv hash table fail\n");
        goto free_hash;
    }

    if (hash_table_size_aligned != ht->len)
        memset(ht->padding, 0, hash_table_size_aligned - ht->len);

    memset(digest, 0, SM3_DIGEST_LENGTH);
    sm3(hash_buffer, bios_size+hash_table_size_aligned, digest);
    csv_report_dump_part("measure", digest, SM3_DIGEST_LENGTH);

free_hash:
    free(hash_buffer);

    return ret;
}
