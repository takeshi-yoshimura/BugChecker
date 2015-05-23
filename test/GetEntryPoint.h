/*
 * GetEntryPoint.h
 *
 *  Created on: 2014/06/13
 *      Author: yoshimura
 */

#ifndef GETENTRYPOINT_H_
#define GETENTRYPOINT_H_


struct A {
    unsigned int irq;
    FILE *fp;
    int a;
    int b;
};

int my_probe3(struct A *a);
int my_probe(struct A *a);
int my_open4(struct A *a);

#endif /* GETENTRYPOINT_H_ */
