void d();
void g();

void e(void) {
	g();
}

void f(void) {
}

void b(void) {
	d();
}

void c(void) {
	e();
	f();
}

void a(void) {
	b();
	c();
}
