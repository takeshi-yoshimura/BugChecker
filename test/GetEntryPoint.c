#include<stdio.h>
#include "GetEntryPoint.h"

struct PM {
	int (*suspend)(struct A *a);
	void (*resume)(struct A *a);
};
struct OP {
    int (*open)(struct A *a);
    void (*close)(struct A *a);
    struct PM pm;
    int (*probe)(struct A *a);
};

typedef int irqreturn_t;
extern int request_irq(unsigned int irq, irqreturn_t (*f)(void), unsigned long flags, const char *name, void *dev);


irqreturn_t isr(void) {
    return 0;
}

static int my_open(struct A *a) { return 0; }
static void my_close(struct A *a) { }
static int my_suspend(struct A *a) { return 0; }
static void my_resume(struct A *a) { }

static int my_open2(struct A *a) { return 0; }
static void my_close2(struct A *a) { }
static int my_probe2(struct A *a) { return 0; }
static int my_suspend2(struct A *a) { return 0; }

static int my_open3(struct A *a) { return 0; }
static void my_close3(struct A *a) { }
static int my_suspend3(struct A *a) { return 0; }

static struct OP op = {
		.open = my_open,
		.close = my_close,
		.pm = {
				.suspend = my_suspend,
				.resume = my_resume
		},
		.probe = my_probe /* from GetEntryPoint.h */
};

static void TestInitStruct() {
    struct OP op = { .open = my_open2};
    struct OP op2 = { 
        .close = my_close2,
        .pm = { .suspend = my_suspend2 },
        .probe = my_probe2
    }; //skip some callbacks
	int (*private_open)(struct A *a) = my_open3;
}

static void TestPassRHS(void) {
	struct OP op;
	op.open = my_open3;
	op.pm.suspend = my_suspend3;
	op.probe = my_probe3; /* from GetEntryPoint.h */
	int (*private_close)(void);
	private_close = my_close3;
}

int (*global_open)(struct A *a) = my_open4;

static void TestPassArgument() {
    request_irq(0, isr, 0, "", 0);
}

void TestGlobalFunction(); //should be ignored
void TestGlobalFunction() {
}

