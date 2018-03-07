.PHONY: all
all: ruuviscan

ruuviscan: main.o
	$(CC) $? -lell -ldl -o $@

clean:
	rm -f ruuviscan main.o
