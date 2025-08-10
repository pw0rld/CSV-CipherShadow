#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

void usage(const char *prog) {
    printf("Usage: %s <pid> <vaddr> [size]\n", prog);
    printf("size: Optional parameter, the number of bytes to read, default is 4 bytes\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid pid\n");
        return 1;
    }

    unsigned long vaddr = strtoul(argv[2], NULL, 16);
    if (vaddr == 0) {
        fprintf(stderr, "Invalid virtual address\n");
        return 1;
    }

    // default read 4 bytes
    size_t read_size = 4;
    if (argc == 4) {
        read_size = atoi(argv[3]);
        if (read_size <= 0 || read_size > 64) {
            fprintf(stderr, "Invalid read size, range 1-64 bytes\n");
            return 1;
        }
    }

    // attach to the target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return 1;
    }

    // wait for the process to stop
    int status;
    waitpid(pid, &status, 0);

    // read memory
    unsigned char *buffer = malloc(read_size);
    if (!buffer) {
        perror("Memory allocation failed");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // read by word length
    for (size_t i = 0; i < read_size; i += sizeof(long)) {
        long data = ptrace(PTRACE_PEEKDATA, pid, vaddr + i, NULL);
        if (data == -1 && errno != 0) {
            perror("Failed to read memory");
            free(buffer);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        memcpy(buffer + i, &data, sizeof(long));
    }

    // detach the process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // print the result
    printf("Address 0x%016lx content (%zu bytes):\n", vaddr, read_size);
    printf("Hex: ");
    for (size_t i = 0; i < read_size; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\nASCII: ");
    for (size_t i = 0; i < read_size; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
            printf("%c", buffer[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");

    free(buffer);
    return 0;
}