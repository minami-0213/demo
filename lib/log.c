#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

// i8
void __my_log_8(uint8_t var)
{
    dfsan_label l = dfsan_get_label(var);
    if (l)
    {
        printf("[my-taint-log] type=i8, bytes=[0x%02x], label=%d\n", var, l);
        print_label_tree(l);
    }
}

// i16
void __my_log_16(uint16_t var)
{
    dfsan_label l = dfsan_get_label(var);
    if (l)
    {
        uint8_t bytes[2];
        memcpy(bytes, &var, 2);
        printf("[my-taint-log] type=i16, bytes=[0x%02x, 0x%02x], label=%d\n", bytes[0], bytes[1], l);
        print_label_tree(l);
    }
}

// i32
void __my_log_32(uint32_t var)
{
    dfsan_label l = dfsan_get_label(var);
    if (l)
    {
        uint8_t bytes[4];
        memcpy(bytes, &var, 4);
        printf("[my-taint-log] type=i32, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x], label=%d\n", bytes[0], bytes[1],
               bytes[2], bytes[3], l);
        print_label_tree(l);
    }
}

// i64
void __my_log_64(uint64_t var)
{
    dfsan_label l = dfsan_get_label(var);
    if (l)
    {
        uint8_t bytes[8];
        memcpy(bytes, &var, 8);
        printf("[my-taint-log] type=i64, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x], "
               "label=%d\n",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], l);
        print_label_tree(l);
    }
}

// 通用的
void __my_log_ptr(void *var, size_t size)
{
    dfsan_label l = dfsan_read_label(var, size);
    if (l)
    {
        char bytes[1024];
        memcpy(bytes, var, size);
        printf("[my-taint-log] type=i8*, bytes=[");
        for (size_t i = 0; i < size - 1; i++)
            printf("0x%02x, ", bytes[i]);
        printf("0x%02x", bytes[size - 1]);
        printf("], label=%d\n", l);

        print_label_tree(l);
    }
}

// 分析比较指令的参考值
void __my_log_icmp_i8(uint8_t x, uint8_t y)
{
    dfsan_label l1 = dfsan_get_label(x);
    if (l1)
    {
        printf("[my-taint-log] type=i8, bytes=[0x%02x], cmpbytes[0x%02x], label=%d\n", x, y, l1);
        print_label_tree(l1);
    }
    dfsan_label l2 = dfsan_get_label(y);
    if (l2)
    {
        printf("[my-taint-log] type=i8, bytes=[0x%02x], cmpbytes[0x%02x], label=%d\n", y, x, l2);
        print_label_tree(l2);
    }
}

void __my_log_icmp_i16(uint16_t x, uint16_t y)
{
    uint8_t bytes[2];
    uint8_t cmpbytes[2];
    dfsan_label l1 = dfsan_get_label(x);
    if (l1)
    {
        memcpy(bytes, &x, 2);
        memcpy(cmpbytes, &y, 2);
        printf("[my-taint-log] type=i16, bytes=[0x%02x, 0x%02x], cmpbytes=[0x%02x, 0x%02x], label=%d\n", bytes[0],
               bytes[1], cmpbytes[0], cmpbytes[1], l1);
        print_label_tree(l1);
    }
    dfsan_label l2 = dfsan_get_label(y);
    if (l2)
    {
        memcpy(bytes, &y, 2);
        memcpy(cmpbytes, &x, 2);
        printf("[my-taint-log] type=i16, bytes=[0x%02x, 0x%02x], cmpbytes=[0x%02x, 0x%02x], label=%d\n", bytes[0],
               bytes[1], cmpbytes[0], cmpbytes[1], l2);
        print_label_tree(l2);
    }
}

void __my_log_icmp_i32(uint32_t x, uint32_t y)
{
    uint8_t bytes[4];
    uint8_t cmpbytes[4];
    dfsan_label l1 = dfsan_get_label(x);
    if (l1)
    {
        memcpy(bytes, &x, 4);
        memcpy(cmpbytes, &y, 4);
        printf("[my-taint-log] type=i64, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x], "
               "cmpbytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x], label=%d\n",
               bytes[0], bytes[1], bytes[2], bytes[3], cmpbytes[0], cmpbytes[1], cmpbytes[2], cmpbytes[3], l1);
        print_label_tree(l1);
    }

    dfsan_label l2 = dfsan_get_label(y);
    if (l2)
    {
        memcpy(bytes, &y, 4);
        memcpy(cmpbytes, &x, 4);
        printf("[my-taint-log] type=i64, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x], "
               "cmpbytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x], label=%d\n",
               bytes[0], bytes[1], bytes[2], bytes[3], cmpbytes[0], cmpbytes[1], cmpbytes[2], cmpbytes[3], l2);
        print_label_tree(l2);
    }
}

void __my_log_icmp_i64(uint64_t x, uint64_t y)
{
    uint8_t bytes[8];
    uint8_t cmpbytes[8];
    dfsan_label l1 = dfsan_get_label(x);
    if (l1)
    {
        memcpy(bytes, &x, 8);
        memcpy(cmpbytes, &y, 8);
        printf("[my-taint-log] type=i64, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x], "
               "cmpbytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x], label=%d\n",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], cmpbytes[0], cmpbytes[1],
               cmpbytes[2], cmpbytes[3], cmpbytes[4], cmpbytes[5], cmpbytes[6], cmpbytes[7], l1);
        print_label_tree(l1);
    }

    dfsan_label l2 = dfsan_get_label(y);
    if (l2)
    {
        memcpy(bytes, &y, 8);
        memcpy(cmpbytes, &x, 8);
        printf("[my-taint-log] type=i64, bytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x], "
               "cmpbytes=[0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x], label=%d\n",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], cmpbytes[0], cmpbytes[1],
               cmpbytes[2], cmpbytes[3], cmpbytes[4], cmpbytes[5], cmpbytes[6], cmpbytes[7], l1);
        print_label_tree(l2);
    }
}