namespace eaos_release {
__attribute__((noinline)) int quote_value(int n) {
    return n < 4 ? 19 : n * 7 + 3;
}
}

int main(int argc, char **) {
    return eaos_release::quote_value(argc);
}
