#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void menu()
{
    puts("----------------------");
    puts("         PPaP         ");	
    puts("----------------------");
    puts(" 1. Add fruit         ");
    puts(" 2. Show fruit        ");
    puts(" 3. Eat fruit         ");
    puts(" 4. Exit              ");
    puts("----------------------");
    printf("Your choice :");
}

void add_fruit(char* str, size_t size)
{
    char buf[0x20];
    int choice = 0;
    size_t n;

    while(1)
    {
        puts("What kind of fruit do you want to add?");
        n = read(0, buf, size);
        if(n <= 0)
        {
            puts("read error");
            exit(1);
        }
        if(buf[n - 1] == '\n')
            buf[n - 1] = '\0';
        printf("Are you sure want to add this fruit: %s \n", buf);
        printf("1.yes, 2.no, 3.cancel : ");
        scanf("%d", &choice);
        
        if(choice == 1)
        {
            memcpy(str, buf, n);
            puts("Success, the fruit looks like umai");
            break;
        }
        else if(choice == 3)
        {
            puts("You seem not hungry.");
            break;
        }
    }
}

int main()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    char fruit[0x31];
    int choice = 0;
	while(1){
		menu();
		scanf("%d", &choice);
		switch(choice){
            case 1 :
                add_fruit(fruit, 0x31);
				break ;
			case 2 :
                if(fruit[0] == '\0')
                    puts("You don't have fruit");
                else
                    printf("Here is your fruit: %s\n", fruit);
				break ;
            case 3 :
                if(fruit[0] == '\0')
                    puts("You don't have fruit");
                else
                {
                    puts("Pen Pineapple Apple Pen");
                    memset(fruit, 0, 0x31);
                }
				break ;
            case 4 :
                puts("Goodbye~ PPAP~~");
				return 0;
			default :
				puts("Invalid choice");
				break ;

		}
	}
}
