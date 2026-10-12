volatile int other_counter = 7;
__attribute__((noinline)) static int dup_name(int x) { volatile char buf[200]; buf[0] = (char)x; return buf[0] * 2; }
__attribute__((noinline)) int helper_a(int x) { return dup_name(x) + other_counter; }
__attribute__((noinline)) int helper_b(int x) { return x + 1; }
int __attribute__((weak)) weak_fn(void) { return 1; }
__attribute__((noinline)) int call_ptr(int (*f)(int), int x) { return f(x) + 1; }
