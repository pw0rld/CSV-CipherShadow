#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define PAGEMAP_ENTRY 8
#define GET_PFN(x) ((x) & 0x7FFFFFFFFFFFFF)
#define PFN_PRESENT(x) ((x) & (1ULL << 63))

void usage(const char *prog) {
    printf("Usage: %s <pid>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid pid\n");
        return 1;
    }

    char maps_path[64], pagemap_path[64], exe_link[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);

    // Get the real path of the program
    char exe_realpath[512] = {0};
    ssize_t exe_len = readlink(exe_link, exe_realpath, sizeof(exe_realpath)-1);
    if (exe_len < 0) {
        perror("readlink exe failed");
        return 1;
    }
    exe_realpath[exe_len] = 0;

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("Failed to open maps");
        return 1;
    }

    int pagemap_fd = open(pagemap_path, O_RDONLY);
    if (pagemap_fd < 0) {
        perror("Failed to open pagemap");
        fclose(maps);
        return 1;
    }

    char line[512];
    unsigned long page_size = getpagesize();
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perm[8], path[512] = "";
        int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511s", &start, &end, perm, path);
        
        // Process all segments of the program (excluding heap and stack anonymous segments)
        if (n == 4 && strcmp(path, exe_realpath) == 0) {
            printf("\nProgram segment: %s\n", path);
            printf("Permissions: %s\n", perm);
            printf("Range: 0x%016lx - 0x%016lx\n", start, end);
            
            // Traverse all pages of this segment
            for (unsigned long vaddr = start; vaddr < end; vaddr += page_size) {
                uint64_t pagemap_entry;
                off_t offset = (vaddr / page_size) * PAGEMAP_ENTRY;
                
                if (lseek(pagemap_fd, offset, SEEK_SET) == (off_t)-1) {
                    perror("lseek failed");
                    continue;
                }
                
                ssize_t nread = read(pagemap_fd, &pagemap_entry, PAGEMAP_ENTRY);
                if (nread != PAGEMAP_ENTRY) {
                    perror("read failed");
                    continue;
                }
                
                if (PFN_PRESENT(pagemap_entry)) {
                    unsigned long pfn = GET_PFN(pagemap_entry);
                    unsigned long page_offset = vaddr & (page_size - 1);  // Calculate page offset
                    unsigned long phy_addr = (pfn << 12) | page_offset;   // Calculate physical address using bit shift
                    printf("Virtual address: 0x%016lx -> Physical address: 0x%016lx\n", vaddr, phy_addr);
                }
            }
        }
    }

    fclose(maps);
    close(pagemap_fd);
    return 0;
}