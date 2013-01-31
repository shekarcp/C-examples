#!/bin/bash

find . -type f -name "*.[ch]" > cscope.files
cscope -bq

ctags -R --fields=+lS /usr/include