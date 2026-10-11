#include <stdint.h>
volatile int counter = 5;               /* .data */
volatile int zeroed_buffer[256];        /* .bss */
const char message[] = "hello embedded"; /* .rodata */
static volatile int file_local = 3;     /* static, .data */
int helper_a(int x);
int helper_b(int x);
__attribute__((noinline)) static int dup_name(int x) { volatile int pad[16]; pad[0] = x; return pad[0] + file_local; }
__attribute__((noinline)) int big_function(int n) {
    volatile int arr[64];
    for (int i = 0; i < 64; i++) arr[i] = n * i;
    int s = 0; for (int i = 0; i < 64; i++) s += arr[i];
    return s + dup_name(n) + helper_a(n);
}
__attribute__((noinline)) int fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }
int main(void) {
    counter += big_function(counter) + helper_b(2) + fact(5);
    zeroed_buffer[3] = message[0];
    return counter;
}
