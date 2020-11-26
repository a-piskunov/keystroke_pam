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
#include <stdbool.h>
#include <time.h>

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

char *
getuidname(uid_t uid)
{
    struct passwd *pw;
    static char username[256];

    pw = getpwuid(uid);
    if (pw == NULL)
        return NULL;

    strncpy(username, pw->pw_name, sizeof(username));
    username[sizeof(username) - 1] = '\0';

    return username;
}

#define KEYBOARD_FILE "/dev/input/event3"
#define KEYSTROKE_FILE "/home/alexey/Documents/keystroke-pam"

int main(int argc, char *argv[])
{
    char pass[PAM_MAX_RESP_SIZE + 1];
    char *option;
    int npass, nullok;
    int blankpass = 0;
    int retval = PAM_AUTH_ERR;
    char *user;
    char *passwords[] = { pass };
//    const char *dev = KEYBOARD_FILE;
    struct input_event ev[64];
    ssize_t n;
    int fd;

    /*
	 * Determine what the current user's name is.
	 * We must thus skip the check if the real uid is 0.
	 */
    if (getuid() == 0) {
        user=argv[1];
    }
    else {
        user = getuidname(getuid());
        /* if the caller specifies the username, verify that user
           matches it */
        if (user == NULL || strcmp(user, argv[1])) {
            user = argv[1];
            /* no match -> permanently change to the real user and proceed */
            if (setuid(getuid()) != 0)
                return PAM_AUTH_ERR;
        }
    }

    fd = open(KEYBOARD_FILE, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_WARNING, "Cannot open %s: %s.\n", KEYBOARD_FILE, strerror(errno));
        return PAM_SYSTEM_ERR;
    }

    /* report to pam */
    char *helper_message = "start!";
    int len = strlen(helper_message);
    if (write(STDOUT_FILENO, helper_message, len) == -1) {
        syslog(LOG_DEBUG, "helper: cannot send message from helper");
        retval = PAM_AUTH_ERR;
    }
    struct pollfd stdin_poll = { .fd = STDIN_FILENO
            , .events = POLLIN | POLLRDBAND | POLLRDNORM | POLLPRI };

    int fd_write;
    time_t rawtime;
    time (&rawtime);
    char name[80];
    sprintf(name,"/home/alexey/Documents/keystroke-pam/data/%s",ctime(&rawtime) );
    char *p = name;
    for (; *p; ++p)
    {
        if (*p == ' ')
            *p = '_';
    }
    syslog(LOG_WARNING, "support: try to open file");
    fd_write = open(name, O_WRONLY | O_CREAT, 0644);
    syslog(LOG_WARNING, "support: file opened");
    if (fd_write == -1) {
        syslog(LOG_WARNING, "support: open failed");
        exit(1);
    }

    bool entering_password = true;
    while (entering_password) {
        /* check password receiving from pam */
        if (poll(&stdin_poll, 1, 0) == 1) {
            npass = pam_read_passwords(STDIN_FILENO, 1, passwords);
            printf("%d", npass);
            if (npass != 1) {    /* is it a valid password? */
                printf("no password supplied");
                *pass = '\0';
            }

            if (*pass == '\0') {
                blankpass = 1;
            }
            entering_password = false;
        }

        /* read current available events */
        struct timeval timeout;
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd,&set);

        timeout.tv_sec = 0;
        timeout.tv_usec = 150000;
        int rv;
        rv = select(fd + 1, &set, NULL, NULL, &timeout);
        if(rv == -1)
            syslog(LOG_WARNING, "helper: select error"); /* an error accured */
        else if(rv == 0)
            syslog(LOG_WARNING, "helper: select timeout");
        else { /* there was data to read */
            n = read(fd, ev, sizeof(ev));
            if (n == (ssize_t) -1) {
//            if (errno == EINTR)
//                continue;
//            else
//                break;
                syslog(LOG_WARNING, "-1 while reading events");
                return PAM_SYSTEM_ERR;
            } else {
//        if (n != sizeof ev) {
//            errno = EIO;
////            break;
//        }
                for (int i = 0; i < n / sizeof(struct input_event); i++) {
                    if (ev[i].type == EV_KEY && ev[i].value >= 0 && ev[i].value <= 2) {
                        dprintf(fd_write, "user %s Event: time %ld.%06ld, %s 0x%04x (%d)\n", user, ev[i].time.tv_sec,
                                ev[i].time.tv_usec, evval[ev[i].value], (int) ev[i].code, (int) ev[i].code);
                    }
                }
            }

        }


    }
    close(fd);
    close(fd_write);
//    printf("%s", pass);
    return PAM_SUCCESS;

}
