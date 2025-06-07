#include <stdio.h>
#include <stdlib.h>

#include "csv_status.h"



void print_random(uint32_t *buf, uint32_t len)
{
    int i;
    for (i=0; i<len; i++){
        printf("%u ", *buf);
        buf++;
    }
    printf("\n");
}

int main()
{
    int ret, len = 400;
    uint8_t* buf = (uint8_t*)malloc(len);

    ret = TCM_GetRandom(buf, len);

    if (ret) {
        printf("get random fail\n");
        free(buf);
        return -1;
    }

    print_random((uint32_t*)buf, (len+3)/4);
    free(buf);

    uint32_t *status = (uint32_t*)malloc(sizeof(uint32_t));

    ret = csv_get_status(status);

    printf("status: %d\n", *status);
    free(status);

    return ret;
}
