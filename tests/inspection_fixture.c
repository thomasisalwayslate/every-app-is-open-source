#include <stdio.h>

__attribute__((noinline)) int inspection_helper(int n) { return n * 3 + 7; }
__attribute__((noinline)) int inspection_error(int n) {
    puts("inspection fixture error marker");
    return n - 11;
}

#define STEP(k) if (n & (k)) { n = inspection_helper(n + (k)); \
    if (n == (k)) return inspection_error(n); }
#define EIGHT(k) STEP(k) STEP(k+1) STEP(k+2) STEP(k+3) \
    STEP(k+4) STEP(k+5) STEP(k+6) STEP(k+7)

__attribute__((noinline)) int inspection_large(int n) {
    puts("inspection fixture large marker");
    EIGHT(1) EIGHT(9) EIGHT(17) EIGHT(25) EIGHT(33) EIGHT(41)
    return n;
}

int main(int argc, char **argv) { return inspection_large(argc); }
