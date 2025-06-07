#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "csv_status.h"
#include "csv_sdk/csv_sdk.h"


static int save_report_to_file(struct csv_attestation_report *report, const char *path)
{
    if (!report) {
        printf("no report\n");
        return -1;
    }
    if (!path || !*path) {
        printf("no file\n");
        return -1;
    }

    int fd = open(path, O_CREAT|O_WRONLY);
    if (fd < 0) {
        printf("open file %s fail %d\n", path, fd);
        return fd;
    }

    int len = 0, n;

    while (len < sizeof(*report)) {
        n = write(fd, report + len, sizeof(*report));
        if (n == -1) {
            printf("write file error\n");
            close(fd);
            return n;
        }
        len += n;
    }

    close(fd);

    return 0;
}

int main()
{
    int ret;
    unsigned int len = sizeof(struct csv_attestation_report);

    unsigned char* report_buf = (unsigned char*)malloc(len);

    ret = ioctl_get_attestation_report(report_buf, len);
    if (ret) {
        printf("get report fail\n");
        free(report_buf);
        return -1;
    }

    ret = save_report_to_file((struct csv_attestation_report*)report_buf, ATTESTATION_REPORT_FILE);
    if (ret) {
        printf("save report fail\n");
        free(report_buf);
        return -1;
    }

    printf("done\n");

    free(report_buf);
    return ret;
}
