
__attribute__((always_inline)) __inline__ int func(int x) {
    x=x+10;
    return x;
}

int main(int artgc, void* argv[]) {
    int a = 0;
    a = func(a);
    return a;
}


