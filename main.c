#include <fcntl.h>
#include <sanitizer/dfsan_interface.h>
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

void print_label_tree(dfsan_label l)
{
    if (l == 0) // 标签为0，说明未加污点
        return;
    const struct dfsan_label_info *info = dfsan_get_label_info(l);

    // 打印当前标签（只打印叶子节点）
    if (info->l1 == 0 && info->l2 == 0)
        printf("byte: %s\n", info->desc);

    // 递归打印左右子标签
    print_label_tree(info->l1);
    print_label_tree(info->l2);
}

void mytest16(__uint16_t *x)
{
    __u_char *ptr = (__u_char *)x;
    for (int i = 0; i < 8; i++)
    {
        printf("%02x ", *(ptr + i));
    }
    printf("\n");
}

void mytest32(__uint32_t *x)
{
    __u_char *ptr = (__u_char *)x;
    for (int i = 0; i < 8; i++)
    {
        printf("%02x ", *(ptr + i));
    }
    printf("\n");
}

int main()
{
    tiff *tiff_test = (tiff *)malloc(sizeof(tiff));

    int fd = open("./data/not_kitty.tiff", O_RDONLY);
    lseek(fd, 0, SEEK_CUR);
    ssize_t ret = read(fd, &tiff_test->magic_num, 8);
    close(fd);

    printf("%d\n", tiff_test->magic_num);
    printf("%d\n", tiff_test->version);
    printf("%d\n", tiff_test->dir_off);

    mytest16((__uint16_t *)&tiff_test->magic_num);
    mytest32((__uint32_t *)&tiff_test->dir_off);

    return 0;
}