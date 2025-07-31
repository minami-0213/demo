// dfsan_io_wrapper.c
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX 10
static int granularity = 1; // byte level

static void assign_taint_labels(void *buf, long offset, size_t size)
{
    for (size_t i = 0; i < size; i += granularity)
    {
        char num[MAX];
        snprintf(num, MAX, "%lu", offset + i + 1);
        printf("label: %s done\n", num);
        dfsan_label L = dfsan_create_label(num, NULL);
        dfsan_set_label(L, (char *)(buf) + i, granularity);
    }
}

static void assign_taint_labels_exf(void *buf, long offset, size_t ret, size_t count, size_t size)
{
    if (offset < 0)
        offset = 0;
    // if count is not so huge!
    int len = ret * size;
    if (ret < count)
    {
        int res = (count - ret) * size;
        if (res < 1024)
        {
            len += res;
        }
        else
        {
            len += 1024;
        }
    }
    assign_taint_labels(buf, offset, len);
}

__attribute__((visibility("default"))) size_t __dfsw_fread(void *buf, size_t size, size_t count, FILE *fd,
                                                           dfsan_label buf_label, dfsan_label size_label,
                                                           dfsan_label count_label, dfsan_label fd_label,
                                                           dfsan_label *ret_label)
{
    printf("[__dfsw_fread] We're in the fread\n");

    long offset = ftell(fd);
    size_t ret = fread(buf, size, count, fd);

    if (ret > 0)
        assign_taint_labels_exf(buf, offset, ret, count, size);

    *ret_label = 0;
    printf("[__dfsw_fread] We're exiting the fread\n");
    return ret;
}

// __attribute__((visibility("default"))) void *__dfsw_mmap(void *addr, size_t length, int prot, int flags, int fd,
//                                                          off_t offset, dfsan_label addr_label, dfsan_label
//                                                          length_label, dfsan_label prot_label, dfsan_label
//                                                          flags_label, dfsan_label fd_label, dfsan_label offset_label,
//                                                          dfsan_label *ret_label)
// {
//     printf("[__dfsw_mmap] We're in the fread\n");

//     void *ret = mmap(addr, length, prot, flags, fd, offset);
//     if (ret != MAP_FAILED)
//         assign_taint_labels(addr, offset, length);

//     *ret_label = 0;
//     printf("[__dfsw_mmap] We're exiting the fread\n");
//     return ret;
// }

// __attribute__((visibility("default"))) int __dfsw_munmap(void *addr, size_t length, dfsan_label addr_label,
//                                                          dfsan_label length_label, dfsan_label *ret_label)
// {
//     printf("[__dfsw_mumap] We're in the fread\n");

//     int ret = munmap(addr, length);
//     dfsan_set_label(0, addr, length);

//     *ret_label = 0;
//     printf("[__dfsw_mumap] We're in the fread\n");
//     return ret;
// }

__attribute__((visibility("default"))) void *__my_mmap(void *addr, size_t length, int prot, int flags, int fd,
                                                       off_t offset)
{
    printf("[__my_mmap] We're in the fread\n");

    void *ret = mmap(addr, length, prot, flags, fd, offset);
    if (ret != MAP_FAILED)
        assign_taint_labels(ret, offset, length);

    printf("[__my_mmap] We're exiting the fread\n");
    return ret;
}

__attribute__((visibility("default"))) int __my_munmap(void *addr, size_t length)
{
    printf("[__my_mumap] We're in the fread\n");

    int ret = munmap(addr, length);
    dfsan_set_label(0, addr, length);
    printf("Clean all labels!\n");

    printf("[__my_mumap] We're in the fread\n");
    return ret;
}

// 一种妥协方案...
ssize_t __my_read(int fd, void *buf, size_t count)
{
    printf("[__my_read] We're in the read\n");

    long offset = lseek(fd, 0, SEEK_CUR);
    ssize_t ret = read(fd, buf, count);

    if (ret > 0)
        assign_taint_labels_exf(buf, offset, ret, count, 1);

    printf("[__my_read] We're exiting the read\n");
    return ret;
}

// 这个 wrapper 抢不过 dfsan 自己实现的
// __attribute__((visibility("default"))) ssize_t __dfsw_read(int fd, void *buf, size_t count, dfsan_label fd_label,
//                                                            dfsan_label buf_label, dfsan_label count_label,
//                                                            dfsan_label *ret_label)
// {
//     printf("[__dfsw_read] We're in the read\n");
//     long offset = lseek(fd, 0, SEEK_CUR);
//     ssize_t ret = read(fd, buf, count);

//     if (ret > 0)
//         assign_taint_labels_exf(buf, offset, ret, count, 1);

//     *ret_label = 0;
//     printf("[__dfsw_read] We're exiting the read\n");
//     return ret;
// }
