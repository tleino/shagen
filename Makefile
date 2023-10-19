CFLAGS=-Wall -pedantic -ansi
LDFLAGS=
LIBS=-lcrypto
PROG=shagen
SRC=passphrase.c shagen.c
OBJ=$(SRC:.c=.o)
$(PROG): $(OBJ)
	$(CC) -o$(PROG) $(OBJ) $(LDFLAGS) $(LIBS)
.c.o:
	$(CC) $(CFLAGS) -c $<
clean:
	rm -f $(OBJ) $(PROG)


