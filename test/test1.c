#include <fcntl.h>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    char buffer[20];

    FILE *fp;
    fp = fopen("./data/data.txt", "rw+");
    fseek(fp, 0, SEEK_SET);
    fread(buffer, sizeof(char), 5, fp);
    // printf("%s\n", buffer);

    char c = buffer[1] + buffer[3];
    if (c == buffer[0])
        printf("Yes\n");
    else
        printf("No\n");

    fclose(fp);
    return 0;
}