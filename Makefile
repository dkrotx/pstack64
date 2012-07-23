LIBS=-lunwind -lunwind-ptrace -lunwind-x86_64

unwind: unwind.c
	$(CC) -g -Wall -Werror -o $@ $^ ${LIBS}

clean:
	$(RM) unwind
