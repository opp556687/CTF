all: sec

sec: sec.c sec.asm
	nasm -felf64 sec.asm -o sec.o
	gcc sec.o sec.c -no-pie -o sec
