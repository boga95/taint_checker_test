/*
A collection of tests for my thesis to compare different taint checkers:
    - Clang Static Analyzer
    - Clang Static Analyzer extension
    - Coverity
    - Infer
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
    int num;
    // Assume fscanf propagate taintedness
    fscanf(fptr, "%d", &num);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

// void testSourcesVscanf(const char* fmt, ...) {
//     va_list arg_ptr;
//     va_start(arg_ptr, fmt);
//     int rc = vscanf(fmt, arg_ptr);
//     va_end(arg_ptr);
//     Buffer[x] = 1; // Expect: Out of bound memory access
// }

#define AF_UNIX   1   /* local to host (pipes) */
#define AF_INET   2   /* internetwork: UDP, TCP, etc. */
#define AF_LOCAL  AF_UNIX   /* backward compatibility */
#define SOCK_STREAM 1

void testSourcesSocket() {
    char buffer[BUFSIZE];
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    read(sock, buffer, BUFSIZE);
    sprintf(buffer, ""); // Expect: Uncontrolled format string
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
    str::getline(myfile, str);
    myfile.close();
    sprintf(str.c_str(), ""); // Expect: Uncontrolled format string
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
    strcpy(str1, str2);
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
    syslog(LOG_WARNING, str); // Expect: Untrusted data is passed to a system call
}

void testSinksSystem() {
    char str[BUFSIZE];
    scanf("%s", str);
    system(LOG_WARNING, str); // Expect: Untrusted data is passed to a system call
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
    memcpy(buf1, buf2, x) // Expect: Untrusted data is used to specify the buffer size
}

void testSinksTaintedBufferSize2() {
    int x;
    scanf("%d", &x);
    malloc(x) // Expect: Untrusted data is used to specify the buffer size
}