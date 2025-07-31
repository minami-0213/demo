#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    int fd = open("./data/not_kitty.tiff", O_RDONLY);
    struct stat stFile;
    __off_t fileSize;

    fstat(fd, &stFile);
    fileSize = stFile.st_size;

    void *base = (void *)mmap(0, (size_t)fileSize, PROT_READ, MAP_SHARED, fd, 0);

    u_int8_t *ptr = (u_int8_t *)base;
    for (int i = 0; i < fileSize; i++)
    {
        printf("%02x ", *(ptr + i));
    }
    printf("\n");

    munmap(base, fileSize);

    return 0;
}