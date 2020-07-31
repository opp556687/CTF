#include<stdio.h>

void getShell()
{
  system("/bin/sh");
}

void vuln()
{
  int i = 0;
  char buf[120];
  for(i=0; i<=1; i++)
  {
    read(0, buf, 0x200);
    printf(buf);
  }
}

int main()
{
  puts("Wellcome!");
  vuln();
  return 0;
}

