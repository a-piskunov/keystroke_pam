all:
	gcc -fPIC -fno-stack-protector -c pam_keystroke.c
	sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_keystroke.so     pam_keystroke.o
	sudo chmod 644 /lib/x86_64-linux-gnu/security/pam_keystroke.so
	sudo gcc keystroke_helper.c manhattan.c -o /usr/sbin/keystroke_helper -lm
	sudo chown root /usr/sbin/keystroke_helper
	sudo chmod u+s /usr/sbin/keystroke_helper