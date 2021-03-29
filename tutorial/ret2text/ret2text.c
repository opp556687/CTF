#include<stdlib.h>

void neveruse()
{
  system("/bin/sh");
}

void vuln()
{
  char buf[16];
  gets(buf);
  printf("hahaha");
}

int main()
{
  vuln();
  return 0;
}
