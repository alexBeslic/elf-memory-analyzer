namespace app {
__attribute__((noinline)) int scale(int x) { volatile int t[8]; t[0] = x; return t[0] * 2; }
__attribute__((noinline)) double scale(double x) { return x * 2.0; }
struct Widget { int v; __attribute__((noinline)) int get() const; };
int Widget::get() const { return v + 1; }
}
int cxx_entry(int a) { app::Widget w{a}; return app::scale(a) + (int)app::scale(1.5) + w.get(); }
