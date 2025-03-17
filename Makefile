CC=gcc
CFLAGS = -I.

container: container.c
	$(CC) -o container $< $(CFLAGS)

clean:
	rm container
