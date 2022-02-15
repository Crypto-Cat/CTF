#include <stdio.h>
#include <string.h>

void hacked() {
    puts("Wait, how did you get in here?!");
}

void vuln() {
    char buffer[64];

    puts("You'll never beat my state of the art stack protector!");
    gets(buffer);
    printf(buffer);

    puts("\nWho said gets() is dangerous? Good luck with your BOF attack :P");
    gets(buffer);
}

int main() {
    vuln();
}