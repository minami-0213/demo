#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    char buffer[20];

    int fd = open("./data/data.txt", O_RDONLY);
    lseek(fd, 0, SEEK_CUR);
    ssize_t ret = read(fd, buffer + 1, 10);
    close(fd);
    printf("%s\n", buffer + 1);

    // some operations
    char c = buffer[1] + buffer[3];
    char x = c | buffer[4] | buffer[2];

    // icmp inst
    if (x == buffer[5])
        printf("Yes\n");
    else
        printf("No\n");

    return 0;
}