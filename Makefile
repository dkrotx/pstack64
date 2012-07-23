LIBS=-lunwind -lunwind-ptrace -lunwind-x86_64

unwind: unwind.c
	$(CC) -o $@ $^ ${LIBS}

clean:
	$(RM) unwind
