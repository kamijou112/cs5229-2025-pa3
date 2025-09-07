#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define SHM_NAME "/monitoring_shm"

typedef struct
{
    uint32_t hh_threshold;
    uint32_t drop_threshold;
} Threshold;

int main(int argc, char *argv[]) {
    int fd = shm_open(SHM_NAME, O_RDWR, 0);
    if (fd == -1) {
        perror("shm_open");
        return 1;
    }

    size_t size = sizeof(Threshold);
    Threshold *threshold = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (threshold == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-hht") == 0 && i + 1 < argc) {
            threshold->hh_threshold = atoi(argv[++i]);
            printf("hh_threshold set to %u\n", threshold->hh_threshold);
        } else if (strcmp(argv[i], "-dt") == 0 && i + 1 < argc) {
            threshold->drop_threshold = atoi(argv[++i]);
            printf("drop_threshold set to %u\n", threshold->drop_threshold);
        } else {
            fprintf(stderr, "Usage: %s [-hht <hh_threshold>] [-dt <drop_threshold>]\n", argv[0]);
            munmap(threshold, size);
            close(fd);
            return 1;
        }
    }

    munmap(threshold, size);
    close(fd);
    return 0;
}