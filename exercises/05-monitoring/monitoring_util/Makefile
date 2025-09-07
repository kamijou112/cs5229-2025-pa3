CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -pthread -lrt

TARGET  = monitoring_util
SRCS    = monitoring_util.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)