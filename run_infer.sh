#!/bin/sh

cd config

echo "Run analysis"
infer run --quandary-only -- clang ../tests.cpp -c

echo "Cleaning up"
rm tests.o
rm -rf infer-out
cd ..