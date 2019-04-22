MONITOR_OBJ = monitor.o system_sniffer.o

monitor: $(MONITOR_OBJ)
	g++ -o $@ $(MONITOR_OBJ) -lpcap -std=c++11

monitor.o: monitor.cpp system_sniffer.h
	g++ -c monitor.cpp -std=c++11

system_sniffer.o: system_sniffer.cpp system_sniffer.h
	g++ -c system_sniffer.cpp -std=c++11

.PHONY: clean

clean:
	rm *.o

# libsniffer.o: sniffer.c sniffer.h
#     gcc -c -fPIC -o $@ sniffer.c
#
# libsniffer.so: libsniffer.o sniffer.h
#     gcc -shared -o libsniffer.so libsniffer.o
