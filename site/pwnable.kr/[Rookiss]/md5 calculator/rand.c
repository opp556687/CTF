#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main()
{
    srand(time(0));
    for(int i=0; i<8; i++)
    {
        int r = rand();
        printf("%d\n", r);
    }
    return 0;
}