#/bin/bash
gcc -o lifl lifl.c -Wall -D_FILE_OFFSET_BITS=64 -DHAVE_UTIMENSAT -DHAVE_POSIX_FALLOCATE -DHAVE_SETXATTR -I/usr/include/mysql/ -L/lib/ -lfuse -L/usr/lib/x86_64-linux-gnu/ -lmysqlclient
ls -lah lifl
