#include <stdio.h>
__attribute__((noinline)) int quote(int n) { return n < 4 ? 19 : n * 7 + 3; }
int main(int argc, char **argv) { puts("eaos fixture anchor"); return quote(argc); }
