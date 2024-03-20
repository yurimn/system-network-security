#Makefile

all: add-nbo

add-nbo: main.o
	g++ -o add-nbo main.o

main.o: main.cpp

clean:
	rm -f add-nbo
	rm -f main.o
