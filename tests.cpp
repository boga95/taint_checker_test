/*
A collection of tests for my thesis to compare different taint checkers:
    - Clang Static Analyzer
    - Clang Static Analyzer extension
    - Coverity
    - Infer
*/

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>

#define BUFSIZE 10
int Buffer[BUFSIZE];

/*
 * Test sources
 * Assumptions:
 *  - checkers give warning for out of boung memory access
 *  - checkers give warning for tainted format string
 *  - fscanf propagate taintedness
 *  - read propagate taintedness
 */

// C
void testSourcesScanf() {
    int x;
    scanf("%d", &x);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

void testSourcesFscanf() {
    FILE *fptr = fopen("example.txt", "r");
    int x;
    fscanf(fptr, "%d", &x);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

// void testSourcesVscanf(const char* fmt, ...) {
//     va_list arg_ptr;
//     va_start(arg_ptr, fmt);
//     int rc = vscanf(fmt, arg_ptr);
//     va_end(arg_ptr);
//     Buffer[x] = 1; // Expect: Out of bound memory access
// }

void testSourcesSocket() {
    char buffer[BUFSIZE];
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    read(sock, buffer, BUFSIZE);
    char result[BUFSIZE];
    sprintf(result, buffer); // Expect: Uncontrolled format string
}

// C++
void testSourcesStdcin() {
    int x, y;
    std::cin >> x >> y;
    Buffer[y] = 1; // Expect: Out of bound memory access
}

void testSourcesStdifstream() {
    int x, y;
    std::ifstream myfile;
    myfile.open("example.txt");
    myfile >> x >> y;
    myfile.close();
    Buffer[y] = 1; // Expect: Out of bound memory access
}

void testSourcesStdgetline() {
    std::string str;
    std::ifstream myfile;
    myfile.open("example.txt");
    std::getline(myfile, str);
    myfile.close();
    char buf[BUFSIZE];
    sprintf(buf, str.c_str(), ""); // Expect: Uncontrolled format string
}


/*
 * Test propagation
 * Assumptions:
 *  - scanf give tainted value
 *  - checkers give warning for out of boung memory access
 *  - checkers give warning for tainted format string
 */

// Propagation through functions
void testPropagationStrcpy() {
    char str1[BUFSIZE];
    char str2[BUFSIZE];
    scanf("%s", str1);
    strcpy(str2, str1);
    char result[BUFSIZE];
    sprintf(result, str2, ""); // Expect: Uncontrolled format string
}

void testPropagationSprintf() {
    char str1[BUFSIZE];
    char str2[BUFSIZE];
    scanf("%s", str1);
    sprintf(str2, "%s", str1);
    char result[BUFSIZE];
    sprintf(result, str2, ""); // Expect: Uncontrolled format string
}

void testPropagationMemcpy() {
    char str1[BUFSIZE];
    char str2[BUFSIZE];
    scanf("%s", str1);
    memcpy(str2, str1, BUFSIZE);
    char result[BUFSIZE];
    sprintf(result, str2, ""); // Expect: Uncontrolled format string
}

void testPropagationAtoi() {
    char str[BUFSIZE];
    scanf("%s", str);
    int x = atoi(str);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

// Propagation through expressions
void testPropagationAssignment1() {
    int x;
    scanf("%d", &x);
    int y = 1;
    int z = x = y;
    Buffer[z] = 1; // Expect: no warning
}

void testPropagationAssignment2() {
    int x;
    scanf("%d", &x);
    int z = x;
    Buffer[z] = 1; // Expect: Out of bound memory access
}

void testPropagationArithmetic1() {
    int x;
    scanf("%d", &x);
    int y = x % BUFSIZE;
    Buffer[y] = 1; // Expect: no warning
}

void testPropagationArithmetic2() {
    int x;
    scanf("%d", &x);
    int y = ((x + 3 - 1) / 5) * 6;
    Buffer[y] = 1; // Expect: Out of bound memory access
}

void testPropagationCompoundAssignment1() {
    int x;
    scanf("%d", &x);
    x %= BUFSIZE;
    Buffer[x] = 1; // Expect: no warning
}

void testPropagationCompoundAssignment2() {
    int x;
    scanf("%d", &x);
    x += 2;
    x -= 2;
    x *= 2;
    x /= 2;
    Buffer[x] = 1; // Expect: Out of bound memory access
}

void testPropagationIncrement() {
    int x;
    scanf("%d", &x);
    ++x;
    x++;
    --x;
    x--;
    Buffer[x] = 1; // Expect: Out of bound memory access
}

void testPropagationConditional() {
    int x;
    scanf("%d", &x);
    int y = x == 4 ? 1 : 2;
    Buffer[y] = 1; // Expect: no warning
}

/*
 * Test sinks
 * Assumptions:
 *  - scanf give tainted value
 */

void testSinksSyslog() {
    char str[BUFSIZE];
    scanf("%s", str);
    syslog(LOG_WARNING, str); // Expect: Uncontrolled format string
}

void testSinksSystem() {
    char str[BUFSIZE];
    scanf("%s", str);
    system(str); // Expect: Untrusted data is passed to a system call
}

void testSinksBufferOverflow() {
    int x;
    scanf("%d", &x);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

void testSinksDivzero1() {
    int x;
    scanf("%d", &x);
    if (x != 0)
        int y = 1 / x; // Expect: no warning
}

void testSinksDivzero2() {
    int x;
    scanf("%d", &x);
    int y = 1 / x; // Expect: Division by a tainted value, possibly zero
}

void testSinksDivzero3() {
    int x;
    scanf("%d", &x);
    int y = 1 % x; // Expect: Division by a tainted value, possibly zero
}

void testSinksTaintedBufferSize1() {
    int x;
    scanf("%d", &x);
    char buf1[BUFSIZE];
    char buf2[BUFSIZE];
    memcpy(buf1, buf2, x); // Expect: Untrusted data is used to specify the buffer size
}

void testSinksTaintedBufferSize2() {
    int x;
    scanf("%d", &x);
    malloc(x); // Expect: Untrusted data is used to specify the buffer size
}

/*
 * Test interprocedural checking
 * Assumptions:
 *  - scanf give tainted value
 */

void sinkFunc(int x) {
  Buffer[x] = 1; // Expect: Out of bound memory access
}

void testInterprocedural() {
    int x;
    scanf("%d", &x);
    sinkFunc(x);
}

/*
 * Test global variable taintedness
 * Assumptions:
 *  - socket give tainted file descriptor
 *  - read propagate taintedness
 */

int global;
int getGlobal() {
  return global;
}

void taintGlobal(int fd) {
  read(fd, &global, sizeof(global));
}

void testGlobal() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    taintGlobal(fd);
    Buffer[getGlobal()] = 1; // Expect: Out of bound memory access
}

/*
 * Test namespaces, scopes
 * Assumptions:
 *  - checkers give warning for out of boung memory access
 */

namespace myNamespace {
    void scanf(const char*, int*);
}

void testNamespace() {
    int x;
    myNamespace::scanf("%d", &x);
    Buffer[x] = 1; // Expect: no warning
}

struct Foo {
    void scanf(const char*, int*);
    void myScanf(const char*, int*);
};

void testMemberFunction() {
    int x;
    Foo foo;
    foo.scanf("%d", &x);
    Buffer[x] = 1; // Expect: no warning
}

/*
 * Test configuration
 * Assumptions:
 */

int mySource();
int myPropagator(int, int*);
void mySink(int, int);
void myFilter(int*);

void testConfiguration() {
    int x = mySource();
    int y;
    myPropagator(x, &y);
    mySink(1, y); // Expect: Untrusted data passed to sink
}

void testConfigurationFilter() {
    int x = mySource();
    int y;
    myPropagator(x, &y);
    myFilter(&y);
    mySink(1, y); // Expect: no warning
}

void testConfigurationMemberFunc() {
    int y;
    Foo foo;
    foo.myScanf("%d", &y);
    mySink(1, y); // Expect: Untrusted data passed to sink
}

int main() {}
