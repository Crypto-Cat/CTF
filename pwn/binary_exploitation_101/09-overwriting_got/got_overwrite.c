#include <stdio.h>
#include <string.h>

void vuln() {
    char buffer[300];
    
    while(1) {
        fgets(buffer, sizeof(buffer), stdin);
        printf(buffer);
    }
}

int main() {
    setuid(0);
    setgid(0);

    vuln();

    return 0;
}