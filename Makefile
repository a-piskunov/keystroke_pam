all:
	gcc -fPIC -fno-stack-protector -c keystroke_pam.c
	sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/keystroke_pam.so     keystroke_pam.o
	sudo gcc binary_helper.c manhattan.c -o /usr/sbin/binary_helper -lm
	sudo chown root /usr/sbin/binary_helper
	sudo chmod u+s /usr/sbin/binary_helper