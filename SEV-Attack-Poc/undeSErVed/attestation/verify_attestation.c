#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "openssl/err.h"

#include "csv_status.h"
#include "csv_sdk/csv_sdk.h"

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

int main(int argc,char *argv[])
{
    int ret = 0;
    int verify_chain;
    const char *report_file;

    if(argc < 3){
        printf("Usage: %s <verify_chain> <report_file>\n", argv[0]);
        printf("  verify_chain: true/false\n");
        printf("  report_file: path to attestation report file\n");
        return -1;
    }

    if(!strncasecmp(argv[1],"true",4)){
        verify_chain = 1;
    }else if(!strncasecmp(argv[1],"false",5)){
        verify_chain = 0;
    }else{
        printf("Error: Invalid verify_chain parameter\n");
        return -1;
    }

    report_file = argv[2];

    unsigned int len = sizeof(struct csv_attestation_report);

    unsigned char* report_buf = (unsigned char*)malloc(len);

    printf("load attestation report from %s\n", report_file);
    ret = load_data_from_file(report_file, report_buf, len);
    if (ret) {
        printf("load report from file fail\n");
        return ret;
    }

    ret = verify_attestation_report(report_buf, len, verify_chain);
    if (ret) {
        printf("verify report fail\n");
        free(report_buf);
        return -1;
    }

    free(report_buf);
    return ret;
}