all : send_arp

send_arp: send_arp.o
	g++ -o send_arp send_arp.o -lpcap

send_arp.o:
	g++ -c send_arp.cpp

clean:
	rm -f *.o
