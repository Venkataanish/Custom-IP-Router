all: router arptest
 
router: router.c arp.c arp.h
	g++ -Wall -o router router.c arp.c -lpcap -pedantic
	
arptest:arptest.c arp.c arp.h
	g++ -o arptest arptest.c arp.c

clean:
	rm -f *.o router 
