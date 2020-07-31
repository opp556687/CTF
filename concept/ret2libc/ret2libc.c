#include <stdio.h>
#include <string.h>

void vul(char *msg)
{
    char buffer[64];
    strcpy(buffer,msg);
    return;
}

int main()
{
    puts("So plz give me your shellcode:");
    char buffer[256];
    memset(buffer,0,256);
    read(0,buffer,256);
    vul(buffer);
    return 0;
}
