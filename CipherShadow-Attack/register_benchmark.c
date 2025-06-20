#include <stdio.h>

void run_benchmark_pattern() {
    asm volatile (
        "start:\n\t"
        "nop\n\t"                    // 0x0
        "push %%r11\n\t"            // 0x1
        "add $0x1, %%r11\n\t"       // 0x80
        "add $0x1, %%r9\n\t"        // 0x40
        "add $0x1, %%rdx\n\t"       // 0x10
        "add $0x1, %%rcx\n\t"       // 0x08
        "add $0x1, %%rax\n\t"       // 0x04
        "sub $0x1, %%rax\n\t"       // 0x04
        "sub $0x1, %%rcx\n\t"       // 0x08
        "sub $0x1, %%rdx\n\t"       // 0x10
        "sub $0x1, %%r9\n\t"        // 0x40
        "sub $0x1, %%r11\n\t"       // 0x80
        "pop %%r11\n\t"             // 0x1
        "jmp start\n\t"             // 0x0
        :
        :
        : "r11", "r9", "rdx", "rcx", "rax"
    );
}

int main() {
    printf("Starting benchmark loop...\n");
    run_benchmark_pattern();  // 无限循环
    return 0;
}