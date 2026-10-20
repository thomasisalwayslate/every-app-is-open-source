#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* Static Go-shaped descriptors; the test never executes this program. */
struct GoString { const unsigned char *pointer; uintptr_t length; };
volatile unsigned char zero_fixture[4096];
struct GoString zero_descriptors[2];
const unsigned char fixture_utf8[] = "日本語";
const unsigned char fixture_embedded[] = {'a', 0, 'b', 255};
const struct GoString string_fixture[] = {
    {(const unsigned char *)"hello", 5}, {fixture_utf8, 9},
    {fixture_embedded, 4}, {0, 0}, {0, 5},
    {(const unsigned char *)(uintptr_t)0x123, 3}
};

__attribute__((noinline)) int memory_helper(int n) { puts("memory fixture marker"); return n + 7; }
__attribute__((noinline)) int memory_focus(int n) { return memory_helper(n) + memory_helper(n+1); }
__attribute__((noinline)) int page_helper_0(int n) { return n + 0; }
__attribute__((noinline)) int page_helper_1(int n) { return n + 1; }
__attribute__((noinline)) int page_helper_2(int n) { return n + 2; }
__attribute__((noinline)) int page_helper_3(int n) { return n + 3; }
__attribute__((noinline)) int page_helper_4(int n) { return n + 4; }
__attribute__((noinline)) int page_helper_5(int n) { return n + 5; }
__attribute__((noinline)) int page_helper_6(int n) { return n + 6; }
__attribute__((noinline)) int page_helper_7(int n) { return n + 7; }
__attribute__((noinline)) int page_helper_8(int n) { return n + 8; }
__attribute__((noinline)) int page_helper_9(int n) { return n + 9; }
__attribute__((noinline)) int page_helper_10(int n) { return n + 10; }
__attribute__((noinline)) int page_helper_11(int n) { return n + 11; }
__attribute__((noinline)) int page_helper_12(int n) { return n + 12; }
__attribute__((noinline)) int page_helper_13(int n) { return n + 13; }
__attribute__((noinline)) int page_helper_14(int n) { return n + 14; }
__attribute__((noinline)) int page_helper_15(int n) { return n + 15; }
__attribute__((noinline)) int page_helper_16(int n) { return n + 16; }
__attribute__((noinline)) int page_helper_17(int n) { return n + 17; }
__attribute__((noinline)) int page_helper_18(int n) { return n + 18; }
__attribute__((noinline)) int page_helper_19(int n) { return n + 19; }
__attribute__((noinline)) int page_helper_20(int n) { return n + 20; }
__attribute__((noinline)) int page_helper_21(int n) { return n + 21; }
__attribute__((noinline)) int page_helper_22(int n) { return n + 22; }
__attribute__((noinline)) int page_helper_23(int n) { return n + 23; }
__attribute__((noinline)) int page_helper_24(int n) { return n + 24; }
__attribute__((noinline)) int page_helper_25(int n) { return n + 25; }
__attribute__((noinline)) int page_helper_26(int n) { return n + 26; }
__attribute__((noinline)) int page_helper_27(int n) { return n + 27; }
__attribute__((noinline)) int page_helper_28(int n) { return n + 28; }
__attribute__((noinline)) int page_helper_29(int n) { return n + 29; }
__attribute__((noinline)) int page_helper_30(int n) { return n + 30; }
__attribute__((noinline)) int page_helper_31(int n) { return n + 31; }
__attribute__((noinline)) int page_helper_32(int n) { return n + 32; }
__attribute__((noinline)) int page_helper_33(int n) { return n + 33; }
__attribute__((noinline)) int page_helper_34(int n) { return n + 34; }
__attribute__((noinline)) int page_helper_35(int n) { return n + 35; }
__attribute__((noinline)) int page_helper_36(int n) { return n + 36; }
__attribute__((noinline)) int page_helper_37(int n) { return n + 37; }
__attribute__((noinline)) int page_helper_38(int n) { return n + 38; }
__attribute__((noinline)) int page_helper_39(int n) { return n + 39; }
__attribute__((noinline)) int page_helper_40(int n) { return n + 40; }
__attribute__((noinline)) int page_helper_41(int n) { return n + 41; }
__attribute__((noinline)) int page_helper_42(int n) { return n + 42; }
__attribute__((noinline)) int page_helper_43(int n) { return n + 43; }
__attribute__((noinline)) int page_helper_44(int n) { return n + 44; }
__attribute__((noinline)) int page_helper_45(int n) { return n + 45; }
__attribute__((noinline)) int page_helper_46(int n) { return n + 46; }
__attribute__((noinline)) int page_helper_47(int n) { return n + 47; }
__attribute__((noinline)) int page_helper_48(int n) { return n + 48; }
__attribute__((noinline)) int page_helper_49(int n) { return n + 49; }
__attribute__((noinline)) int page_helper_50(int n) { return n + 50; }
__attribute__((noinline)) int page_helper_51(int n) { return n + 51; }
__attribute__((noinline)) int page_helper_52(int n) { return n + 52; }
__attribute__((noinline)) int page_helper_53(int n) { return n + 53; }
__attribute__((noinline)) int page_helper_54(int n) { return n + 54; }
__attribute__((noinline)) int page_helper_55(int n) { return n + 55; }
__attribute__((noinline)) int page_helper_56(int n) { return n + 56; }
__attribute__((noinline)) int page_helper_57(int n) { return n + 57; }
__attribute__((noinline)) int page_helper_58(int n) { return n + 58; }
__attribute__((noinline)) int page_helper_59(int n) { return n + 59; }
__attribute__((noinline)) int page_helper_60(int n) { return n + 60; }
__attribute__((noinline)) int page_helper_61(int n) { return n + 61; }
__attribute__((noinline)) int page_helper_62(int n) { return n + 62; }
__attribute__((noinline)) int page_helper_63(int n) { return n + 63; }
__attribute__((noinline)) int page_helper_64(int n) { return n + 64; }

__attribute__((noinline)) int call_page_fixture(int n) {
    return page_helper_0(n) +
           page_helper_1(n) +
           page_helper_2(n) +
           page_helper_3(n) +
           page_helper_4(n) +
           page_helper_5(n) +
           page_helper_6(n) +
           page_helper_7(n) +
           page_helper_8(n) +
           page_helper_9(n) +
           page_helper_10(n) +
           page_helper_11(n) +
           page_helper_12(n) +
           page_helper_13(n) +
           page_helper_14(n) +
           page_helper_15(n) +
           page_helper_16(n) +
           page_helper_17(n) +
           page_helper_18(n) +
           page_helper_19(n) +
           page_helper_20(n) +
           page_helper_21(n) +
           page_helper_22(n) +
           page_helper_23(n) +
           page_helper_24(n) +
           page_helper_25(n) +
           page_helper_26(n) +
           page_helper_27(n) +
           page_helper_28(n) +
           page_helper_29(n) +
           page_helper_30(n) +
           page_helper_31(n) +
           page_helper_32(n) +
           page_helper_33(n) +
           page_helper_34(n) +
           page_helper_35(n) +
           page_helper_36(n) +
           page_helper_37(n) +
           page_helper_38(n) +
           page_helper_39(n) +
           page_helper_40(n) +
           page_helper_41(n) +
           page_helper_42(n) +
           page_helper_43(n) +
           page_helper_44(n) +
           page_helper_45(n) +
           page_helper_46(n) +
           page_helper_47(n) +
           page_helper_48(n) +
           page_helper_49(n) +
           page_helper_50(n) +
           page_helper_51(n) +
           page_helper_52(n) +
           page_helper_53(n) +
           page_helper_54(n) +
           page_helper_55(n) +
           page_helper_56(n) +
           page_helper_57(n) +
           page_helper_58(n) +
           page_helper_59(n) +
           page_helper_60(n) +
           page_helper_61(n) +
           page_helper_62(n) +
           page_helper_63(n) +
           page_helper_64(n);
}

int main(int argc, char **argv) { return memory_focus(argc) + call_page_fixture(argc) + zero_fixture[0] + (int)string_fixture[0].length; }
