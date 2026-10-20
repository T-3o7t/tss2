CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I/usr/include/tss2
LDFLAGS = -ltss2-tctildr -ltss2-esys -ltss2-rc -ltss2-mu -lcrypto

TARGET  = attest_flow

SRCS    = attest_flow.c attester.c verifier.c makecred.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

# 使い捨ての swtpm を立ち上げて実行する
.PHONY: run
run: $(TARGET)
	./run-swtpm.sh
