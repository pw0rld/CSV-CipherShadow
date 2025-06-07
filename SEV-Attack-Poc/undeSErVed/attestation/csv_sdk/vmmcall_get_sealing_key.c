#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "csv_status.h"

#include "openssl/sm3.h"


int vmmcall_get_sealing_key(unsigned char* key_buf, unsigned int buf_len)
{
    int ret, i, j;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report.reserved2)){
        logcat("The allocated length is too short to meet the sealing key!\n");
        logcat("The length should not be less than %ld \n", sizeof(report.reserved2));
        return -1;
    }

    if (key_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    ret = get_attestation_report(&report);
    if (ret) {
        logcat("get attestation report fail\n");
        return -1;
    }

    ret = verify_session_mac(&report);
    if (ret) {
        logcat("report hmac verify fail\n");
        return -1;
    }

    j = GUEST_ATTESTATION_NONCE_SIZE / sizeof(uint32_t);
    for (i = 0; i < j; i++)
         ((uint32_t *)r_mnonce)[i] = ((uint32_t *)report.mnonce)[i] ^ report.anonce;

    ret = memcmp(g_mnonce, r_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    if (ret) {
        logcat("mnonce is different\n");
        csv_data_dump("g_mnonce", g_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
        csv_data_dump("r_mnonce", r_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
        return -1;
    }

    memcpy(key_buf, report.reserved2, sizeof(report.reserved2));

    return 0;
}
