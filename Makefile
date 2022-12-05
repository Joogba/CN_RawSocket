all : main

main : main.c
	gcc main.c -o app

clean :
	rm main