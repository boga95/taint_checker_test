/*
A collection of tests for my thesis to compare different taint checkers:
    - Clang Static Analyzer
    - Clang Static Analyzer extension
    - Coverity
    - Infer
*/

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>

#define BUFSIZE 10
int Buffer[BUFSIZE];

/*
 * Test sources
 */

// C
void testSources1() {
    int x;
    scanf("%d", &x);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

void testSources2() {
    FILE *fptr = fopen("example.txt", "r");
    int num;
    // Assume fscanf propagate taintedness
    fscanf(fptr, "%d", &num);
    Buffer[x] = 1; // Expect: Out of bound memory access
}

#define AF_UNIX   1   /* local to host (pipes) */
#define AF_INET   2   /* internetwork: UDP, TCP, etc. */
#define AF_LOCAL  AF_UNIX   /* backward compatibility */
#define SOCK_STREAM 1

void testSources3() {
    constexpr size_t bufsize = 100;
    char buffer[bufsize];
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // Assume read propagate taintedness
    read(sock, buffer, bufsize);
    syslog(LOG_WARNING, buffer); // Expect: Untrusted data is passed to a system call
}

void testSources4() {
    constexpr size_t bufsize = 100;
    char buffer[bufsize];
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // Assume read propagate taintedness
    read(sock, buffer, bufsize);
    sprintf(buffer, ""); // Expect: Uncontrolled format string
}

void testSources5() {
    constexpr size_t bufsize = 100;
    char buffer[bufsize];
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // Assume read propagate taintedness
    read(sock, buffer, bufsize);
    sprintf(buffer, ""); // Expect: Uncontrolled format string
}

// C++
void testSources6() {
    int x, y;
    std::cin >> x >> y;
    Buffer[y] = 1; // Expect: Out of bound memory access
}

void testSources7() {
    int x, y;
    std::ifstream myfile;
    myfile.open("example.txt");
    myfile >> x >> y;
    myfile.close();
    Buffer[y] = 1; // Expect: Out of bound memory access
}

void testSources8() {
    std::string str;
    std::ifstream myfile;
    myfile.open("example.txt");
    str::getline(myfile, str);
    myfile.close();
    sprintf(str.c_str(), ""); // Expect: Uncontrolled format string
}