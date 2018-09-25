sniffex: main.cc c-ipcrypt/ipcrypt.c
	$(CC) -o gcc -o hitbook main.cc c-ipcrypt/ipcrypt.c -I. -lpcap

.PHONY: clean
clean:
	rm -f sniffex
