#!/bin/bash

cwd=$(dirname "$0")
cd $cwd/hacl-star/dist/gcc-compatible/

./configure
make

cd -
