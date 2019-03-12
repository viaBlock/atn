# SPDX-License-Identifier: GPL-2.0

.PHONY: clean all FORCE

all: chatapp

chatapp: FORCE
	gcc -g -I ../include/ -o chatapp chatapp.c

clean:
	@rm -f *.o chatapp

FORCE: