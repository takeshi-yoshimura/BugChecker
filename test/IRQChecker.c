#include<stdio.h>
struct A {
    unsigned int irq;
    FILE *fp;
    int a;
    int b;
};
#define IRQF_SHARED 0x00000080 // include/linux/interrupt.h
struct OP {
    int (*open)(struct A *a);
    void (*close)(struct A *a);
};

typedef int irqreturn_t;
int request_irq(unsigned int irq, irqreturn_t (*f)(void), unsigned long flags, const char *name, void *dev);
int request_threaded_irq(unsigned int irq, irqreturn_t (*f)(void), irqreturn_t (*g)(void), unsigned long flags, const char *name, void *dev);
void free_irq(unsigned int irq, void *dev) {}
struct A* alloc_test(void);

irqreturn_t isr(void) {
    return 0;
}

int open(struct A *a) {
    return request_irq(a->irq, isr, 0, "", 0);
}
void close(struct A *a) {
    free_irq(a->irq, 0);
}
const static struct OP op = { .open = open, .close = close };
void TestOP() {
    struct A *test = alloc_test();
    struct OP op2 = op;
    int err = op2.open(test);
    return; //should leak
}

irqreturn_t testFreeIrqInISR(void) {
    free_irq(1, 0); //free irq in ISR
    return 0;
}

void TestRequestSharedIRQWithNullDevID() {
    struct A * test = alloc_test();
    int err = request_irq(test->irq, isr, IRQF_SHARED, "", 0); //request shared irq with null dev_id
    if (err)
        return;
    free_irq(test->irq, 0);
}

void TestThreadedRequestSharedIRQWithNullDevID() {
    struct A * test = alloc_test();
    int err = request_threaded_irq(test->irq, NULL, isr, IRQF_SHARED, "", 0); //request shared irq with null dev_id
    if (err)
        return;
    free_irq(test->irq, 0);
}

void TestDoubleRequestUniqueIRQ() {
    struct A * test = alloc_test();
    if (request_irq(test->irq, isr, 0, "", 0)) //legal request
    	return;
    request_irq(test->irq, isr, 0, "", 0); //double request unique irq
    free_irq(test->irq, 0);
}

void TestThreadedDoubleRequestUniqueIRQ() {
    struct A * test = alloc_test();
    if (request_threaded_irq(test->irq, 0, isr, 0, "", 0)) //legal request
    	return;
    request_threaded_irq(test->irq, 0, isr, 0, "", 0); //double request unique irq
    free_irq(test->irq, 0);
}

void TestDoubleRequestSharedIRQ() {
    struct A * test = alloc_test();
    int a;
    if (request_irq(test->irq, isr, IRQF_SHARED, "", &a)) //legal request
    	return;
    request_irq(test->irq, isr, IRQF_SHARED, "", &a); //double request shared irq
    free_irq(test->irq, &a);
}

void TestThreadedDoubleRequestSharedIRQ() {
    struct A * test = alloc_test();
    int a;
    if (request_threaded_irq(test->irq, 0, isr, IRQF_SHARED, "", &a)) //legal request
    	return;
    request_threaded_irq(test->irq, 0, isr, IRQF_SHARED, "", &a); //double request unique irq
    free_irq(test->irq, &a);
}

void TestWrongFree() {
    struct A * test = alloc_test();
    int err = request_irq(test->irq, isr, 0, "", 0);
    if (err)
        return;
    free_irq(1, 0);
}//wrong free (reported as a leak)

void TestThreadedWrongFree() {
    struct A * test = alloc_test();
    int err = request_threaded_irq(test->irq, NULL, isr, 0, "", 0);
    if (err)
        return;
    free_irq(1, 0);
}//wrong free (reported as a leak)

void TestDoubleFree() {
    struct A * test = alloc_test();
    int err = request_irq(test->irq, isr, 0, "", 0);
    if (err)
        return;
    free_irq(test->irq, 0); //legal free
    free_irq(test->irq, 0); //double free
}

void TestThreadedDoubleFree() {
    struct A * test = alloc_test();
    int err = request_threaded_irq(test->irq, NULL, isr, 0, "", 0);
    if (err)
        return;
    free_irq(test->irq, 0); //legal free
    free_irq(test->irq, 0); //double free
}

void TestError() {
    struct A * test = alloc_test();
    request_irq(test->irq, isr, 0, "", 0);
    free_irq(test->irq, 0); //should handle request failure
}

void TestThreadedError() {
    struct A * test = alloc_test();
    request_threaded_irq(test->irq, NULL, isr, 0, "", 0);
    free_irq(test->irq, 0); //should handle request failure
}

void TestLeak() {
    struct A * test = alloc_test();
    request_irq(test->irq, isr, 0, "", 0);
} //should free irq

void TestThreadedLeak() {
    struct A *test = alloc_test();
    request_threaded_irq(test->irq, NULL, isr, 0, "", 0);
    return;
} //should free irq

void func(struct A *a);
void TestEscape() {
	struct A *test = alloc_test();
	if (request_threaded_irq(test->irq, NULL, isr, 0, "", 0))
		return;
	func(test); //escaped
	free_irq(test->irq, 0);
} // never reported

void TestEscape2(struct A test) {
	if (request_threaded_irq(test.irq, NULL, isr, 0, "", 0))
		return;
	func(&test); //escaped
	free_irq(test.irq, 0);
} // never reported

void TestEscape3() {
	struct A *test = alloc_test();
	if (request_irq(test->irq, isr, 0, "", test))
		return;
	free_irq(test->irq, test);
}// legal free
