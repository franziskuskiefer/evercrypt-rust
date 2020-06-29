#!/bin/bash

cwd=$(cd $(dirname $0); pwd -P)
cd $cwd/hacl-star/dist/gcc-compatible/

./configure
make

cd -
