#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include "csv_status.h"

#include "openssl/sm3.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

#define CSV_GUEST_IOC_TYPE     'D'
#define GET_ATTESTATION_REPORT _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

int get_attestation_report_ioctl(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    int user_data_len = PAGE_SIZE;
    long ret;
    int fd = 0;
    struct csv_guest_mem mem = {0};

    if (!report) {
        logcat("NULL pointer for report\n");
        return -1;
    }

    /* prepare user data */
    user_data = (struct csv_attestation_user_data *)malloc(user_data_len);
    if (user_data == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }
    memset((void *)user_data, 0x0, user_data_len);
    logcat("user data: %p\n", user_data);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    logcat("data: %s\n", user_data->data);

    fd = open("/dev/csv-guest",O_RDWR);
    if(fd < 0)
    {
        logcat("open /dev/csv-guest failed\n");
        free(user_data);
        return -1;
    }
    mem.va = (uint64_t)user_data;
    logcat("mem.va: %lx\n", mem.va);
    mem.size = user_data_len;
    /*  get attestation report */
    ret = ioctl(fd,GET_ATTESTATION_REPORT,&mem);
    if(ret < 0)
    {
        logcat("ioctl GET_ATTESTATION_REPORT fail: %ld\n", ret);
        goto error;
    }
    memcpy(report, user_data, sizeof(*report));

    ret = 0;
error:
    close(fd);
    free(user_data);
    return ret;
}

int ioctl_get_attestation_report(unsigned char* report_buf, unsigned int buf_len)
{
    int ret;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report)){
        logcat("The allocated length is too short to meet the generated report!\n");
        logcat("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    logcat("get attestation report & save to %s\n", ATTESTATION_REPORT_FILE);

    ret = get_attestation_report_ioctl(&report);
    if (ret) {
        logcat("get attestation report fail\n");
        return -1;
    }

    ret = verify_session_mac(&report);
    if (ret) {
        logcat("PEK cert and ChipId have been tampered with\n");
        return ret;
    } else {
        logcat("check PEK cert and ChipId successfully\n");
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));

    memcpy(report_buf, &report, sizeof(report));

    return 0;
}
