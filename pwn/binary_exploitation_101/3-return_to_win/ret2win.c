#include <stdio.h>

void hacked()
{
    printf("This function is TOP SECRET! How did you get in here?! :O\n");
}

void register_name()
{
    char buffer[16];

    printf("Name:\n");
    scanf("%s", buffer);
    printf("Hi there, %s\n", buffer);    
}

int main()
{
    register_name();

    return 0;
}