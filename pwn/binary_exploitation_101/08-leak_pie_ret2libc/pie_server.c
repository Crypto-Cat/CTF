#include <stdio.h>

void enter_name(){
    char name[64];
    puts("Please enter your name:");
    fgets(name, sizeof(name), stdin);
    printf("Hello ");
    printf(name);
}

void vuln(){
    char buffer[256];
    gets(buffer);
}

int main()
{
    setuid(0);
    setgid(0);

    enter_name();

    puts("\nGood luck with your ret2libc, you'll never bypass my new PIE protection OR find out where my lib-c library is :P\n");

    vuln();

    return 0;
}