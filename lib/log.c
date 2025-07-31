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
        printf("byte: %d\n", l - 1);

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