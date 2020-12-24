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
#include "manhattan.h"

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
    struct input_event ev[300];
    ssize_t n;
    int fd;
    char keyboard_path[100];
    double score;
    int debug;
    /*
	 * Determine what the current user's name is.
	 * We must thus skip the check if the real uid is 0.
	 */

    user=argv[1];
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
    score = atof(argv[2]);
    strncpy(keyboard_path, argv[3], strlen(argv[3]) + 1);
    syslog (LOG_AUTH|LOG_INFO, "score: %f, keyboard_path: %s", score, keyboard_path);
    fd = open(keyboard_path, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_AUTH|LOG_INFO, "Cannot open %s: %s.\n", keyboard_path, strerror(errno));
        return PAM_SYSTEM_ERR;
    }
    syslog (LOG_AUTH|LOG_INFO, "keyboard opened");

    /* report to pam */
    char *helper_message = "start!";
    int len = strlen(helper_message);
    if (write(STDOUT_FILENO, helper_message, len+1) == -1) {
        syslog(LOG_DEBUG, "helper: cannot send message from helper");
        retval = PAM_AUTH_ERR;
    }
    struct pollfd stdin_poll = { .fd = STDIN_FILENO
            , .events = POLLIN | POLLRDBAND | POLLRDNORM | POLLPRI };

//    int fd_write;
//    time_t rawtime;
//    time (&rawtime);
//    char name[80];
//    sprintf(name,"/home/alexey/Documents/keystroke-pam/data/%s",ctime(&rawtime) );
//    char *p = name;
//    for (; *p; ++p)
//    {
//        if (*p == ' ')
//            *p = '_';
//    }
//    syslog(LOG_WARNING, "support: try to open file");
//    fd_write = open(name, O_WRONLY);
//    syslog(LOG_WARNING, "support: file opened");
//    if (fd_write == -1) {
//        syslog(LOG_WARNING, "support: open failed");
//        exit(1);
//    }

    int ev_offset = 0;

    bool entering_password = true;
    while (entering_password) {
        /* check password receiving from pam */
        if (poll(&stdin_poll, 1, 0) == 1) {
            char to_helper_message[20];
            if (read(STDIN_FILENO, to_helper_message, 20) == -1) {
                syslog(LOG_DEBUG, "helper: cannot send message from helper");
                retval = PAM_AUTH_ERR;
            }
            syslog (LOG_AUTH|LOG_ERR, "helper: end password input");
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
            n = read(fd, ev + ev_offset, sizeof(ev));
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
//          break;
//        }
                ev_offset += n / sizeof(struct input_event);
            }
        }
    }
    struct input_event array_of_actions[100];
    int num_actions = 0;
    int i = 1;
    /* check enter */
    while (ev[i].code == KEY_ENTER) {
        i++;
    }
    for (; i < ev_offset; i++) {
        if (ev[i].type == EV_KEY && ev[i].value >= 0 && ev[i].value <= 1) {
            if (ev[i].code != KEY_ENTER) {
                array_of_actions[num_actions] = ev[i];
                num_actions += 1;
                syslog(LOG_AUTH|LOG_INFO, "helper: user %s Event: time %ld.%06ld, %s 0x%04x (%d)", user, ev[i].time.tv_sec,
                    ev[i].time.tv_usec, evval[ev[i].value], (int) ev[i].code, (int) ev[i].code);
            }
//            dprintf(fd_write, "user %s Event: time %ld.%06ld, %s 0x%04x (%d)\n", user, ev[i].time.tv_sec,
//                    ev[i].time.tv_usec, evval[ev[i].value], (int) ev[i].code, (int) ev[i].code);
        }
    }
    long int last_press_time_sec = 0;
    long int last_press_time_usec = 0;

    double *time_features = malloc((num_actions - 1) * sizeof(*time_features));
    int *correct_keycodes = malloc(num_actions * sizeof(*correct_keycodes));
    int keycodes_num = 0;
    int features_num = 0;
    for (int i = 0; i < num_actions; i++) {
        if (array_of_actions[i].value == 1) {
            correct_keycodes[keycodes_num] = array_of_actions[i].code;
            keycodes_num++;
            if (last_press_time_sec > 0) {
                /* flight */
                double flight = (array_of_actions[i].time.tv_sec - last_press_time_sec) * 1000 +
                                (double) (array_of_actions[i].time.tv_usec - last_press_time_usec) / 1000;
                if ((num_actions - 1) < features_num) {
                    syslog (LOG_AUTH|LOG_ERR, "helper: error while feature extraction");
                    return EXIT_FAILURE;
                }
                time_features[features_num] = flight;
                features_num++;
                printf("flight %f", flight);
            }
            bool not_found_up = true;
            int j = i + 1;
            while (not_found_up && (j < num_actions)) {
                if ((array_of_actions[i].code == array_of_actions[j].code) &&
                    (array_of_actions[j].value == 0)) {
                    /* hold time */
                    double hold =
                            (array_of_actions[j].time.tv_sec - array_of_actions[i].time.tv_sec) * 1000 +
                            (double) (array_of_actions[j].time.tv_usec - array_of_actions[i].time.tv_usec) /
                            1000;
                    if ((num_actions - 1) < features_num) {
                        syslog (LOG_AUTH|LOG_ERR, "helper: error while feature extraction");
                        return EXIT_FAILURE;
                    }
                    time_features[features_num] = hold;
                    features_num++;
                    not_found_up = false;
                }
                j++;
            }
            last_press_time_sec = array_of_actions[i].time.tv_sec;
            last_press_time_usec = array_of_actions[i].time.tv_usec;
        }
    }
    char features[100] = "features: ";
    for (int i = 0; i < features_num; i++) {
        ftoa(1.555, time_features, 2)
    }

    /* read from file */
    char user_file_path[100] = "/etc/keystroke-pam/";
    strcat(user_file_path, user);
    FILE *f = fopen(user_file_path,"r");
    if ( !f ) {
        syslog (LOG_AUTH|LOG_ERR, "Error: Unable to open input file.\n");
//        exit(EXIT_FAILURE);
    }
    int rows, cols;
    double norm_score;
    if ( fscanf(f,"%lf%d%d", &norm_score, &rows, &cols) != 3 ) {
        syslog (LOG_AUTH|LOG_ERR, "Error: wrong file format.\n");
//        exit(EXIT_FAILURE);
    }
    syslog (LOG_AUTH|LOG_INFO, "norm: %lf\n", norm_score);
    syslog (LOG_AUTH|LOG_INFO, "rows, cols %d, %d\n", rows, cols);
    double *passwords_features;
    passwords_features = malloc(rows * cols * sizeof(double));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            fscanf(f,"%lf", &passwords_features[i * cols + j]);
        }
    }
    fclose(f);
    if (cols != features_num) {
        syslog (LOG_AUTH|LOG_ERR, "features_num is not equal: cols=%d, features_num=%d", cols, features_num);
//        exit(EXIT_FAILURE);
    }
    double result_score;
    result_score = score_keystrokes(passwords_features, rows,
                     features_num, time_features, &norm_score);
    syslog (LOG_AUTH|LOG_INFO, "result_score %f", result_score);
    free(passwords_features);
    free(correct_keycodes);
    free(time_features);
    close(fd);

    if (result_score >= score) {
        /* report to pam */
        int res = PAM_SUCCESS;
        if (write(STDOUT_FILENO, &res, sizeof(int)) == -1) {
            syslog(LOG_DEBUG, "helper: cannot send message from helper");
            retval = PAM_AUTH_ERR;
        }
        syslog (LOG_AUTH|LOG_INFO, "PAM_SUCCESS returned");
        exit(PAM_SUCCESS);
    } else {
        /* report to pam */
        int res = PAM_AUTH_ERR;
        if (write(STDOUT_FILENO, &res, sizeof(int)) == -1) {
            syslog(LOG_DEBUG, "helper: cannot send message from helper");
            retval = PAM_AUTH_ERR;
        }
        syslog (LOG_AUTH|LOG_INFO, "PAM_AUTH_ERR returned");
        exit(PAM_AUTH_ERR);
    }
}
