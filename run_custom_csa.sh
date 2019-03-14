#!/bin/sh

scan-build -load-plugin /mnt/win/Shadow/taintchecker/build/lib/libCustomTaintChecker.so -enable-checker alpha.security.taint.CustomTaintPropagation -enable-checker alpha.security.ArrayBoundV2 -analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=config/customTaintCheckerConfig.xml clang tests.cpp -c
rm tests.o