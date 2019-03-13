#!/bin/sh

scan-build -enable-checker alpha.security.taint.TaintPropagation -enable-checker alpha.security.ArrayBoundV2 clang tests.cpp -c
rm tests.o