#!/bin/bash

N=4

for test in `ls -d */*/`; do
    #((i=i%N)); ((i++==0)) && wait
    python3 frederico\'s\ fast\ tls\ handshake\ analyzer.py --folder $test &
done
