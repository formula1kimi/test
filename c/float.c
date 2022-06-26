#include <stdio.h>

int main(int argc, char * argv[]) {
    double a = 0.1, b = 0, c = 0;
    printf("a = %.20f(%x)\n", a, a);
    for (int i = 0; i < 10; i++) 
        b = b + a;
    printf("b = %.20f\n", b);
    c = a * 10;
    printf("c = %.20f\n", c);
    return 0;
}
