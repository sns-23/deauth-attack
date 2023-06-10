CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lpcap
OBJS = main.o util.o

deauth-attack: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f deauth-attack *.o

.PHONY:
	deauth-attack clean