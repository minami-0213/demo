#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct test_format
{
    __uint16_t magic_num;
    __uint16_t version;
    __uint32_t dir_off;
    __uint8_t data[1024];
};

typedef struct test_format tiff;

void mytest(char a, char b)
{
    printf("%c %c\n", a, b);
    return;
}

int main()
{
    // char buffer[1024];

    // FILE *fp;
    // fp = fopen("./data/data.txt", "rw+");
    // fseek(fp, 0, SEEK_SET);
    // fread(buffer + 1, sizeof(char), 5, fp);
    // fclose(fp);
    tiff *tiff_test = (tiff *)malloc(sizeof(tiff));

    int fd = open("./data/not_kitty.tiff", O_RDONLY);
    lseek(fd, 0, SEEK_CUR);
    ssize_t ret = read(fd, &tiff_test->magic_num, 8);
    close(fd);
    // printf("%s\n", buffer + 1);

    printf("%d\n", tiff_test->magic_num);
    printf("%d\n", tiff_test->version);
    printf("%d\n", tiff_test->dir_off);

    char *ptr = (char *)&tiff_test->magic_num;
    for (int i = 0; i < 8; i++)
    {
        printf("%02x ", *(ptr + i));
    }
    printf("\n");

    // some operations
    // char c = buffer[1] + buffer[3];
    // char x = c | buffer[4] | buffer[2];

    // icmp inst
    // if (x == buffer[5])
    //     printf("Yes\n");
    // else
    //     printf("No\n");

    // mytest(x, c);

    return 0;
}