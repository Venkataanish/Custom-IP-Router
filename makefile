all: router
 
router:router.c
	g++ -Wall -o router router.c -lpcap -pedantic
