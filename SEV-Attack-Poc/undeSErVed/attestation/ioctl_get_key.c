#include <stdio.h>
#include <stdlib.h>

#include "csv_status.h"
#include "csv_sdk/csv_sdk.h"

static void print_data(const char* name, uint8_t *data, uint32_t len)
{
    printf("%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        printf("%02hhx", c);
    }
    printf("\n");
}

int main()
{
    int ret;
    struct csv_attestation_report report;

    unsigned int len = sizeof(report.reserved2);

    unsigned char* key_buf = (unsigned char*)malloc(len);

    ret = ioctl_get_sealing_key(key_buf, len);
    if (ret) {
        printf("get sealing key fail\n");
        free(key_buf);
        return -1;
    }

    print_data("sealing key", key_buf, len);

    free(key_buf);
    return ret;
}
