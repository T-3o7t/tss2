CC      = gcc
CFLAGS  = -Wall -O2 -I/usr/include/tss2
LDFLAGS = -ltss2-tctildr -ltss2-sys -ltss2-rc

TARGET  = Test_sys

SRCS    = Test_sys.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)
