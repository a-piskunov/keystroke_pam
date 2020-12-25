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
    int retval = PAM_AUTH_ERR;
    char *user;
    struct input_event ev[300];
    ssize_t n;
    int fd;
    char keyboard_path[100];
    double score;
    int debug;

    user=argv[1];

    score = atof(argv[2]);
    strncpy(keyboard_path, argv[3], strlen(argv[3]) + 1);
    if (argv[4][0] == '0') {
        debug = 0;
    } else {
        debug = 1;
    }
    if (debug) {
        syslog(LOG_AUTH | LOG_INFO, "score: %f, keyboard_path: %s", score, keyboard_path);
    }
    fd = open(keyboard_path, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_AUTH|LOG_ERR, "Cannot open %s: %s.\n", keyboard_path, strerror(errno));
        /* report error to pam */
        int helper_message = 1;
        if (write(STDOUT_FILENO, &helper_message, sizeof(int)) == -1) {
            syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
        }
        return PAM_SYSTEM_ERR;
    }
     /* report to pam */
    int helper_message = 0;
    if (write(STDOUT_FILENO, &helper_message, sizeof(int)) == -1) {
        syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
        retval = PAM_AUTH_ERR;
    }
    syslog(LOG_AUTH|LOG_ERR, "helper: to pam");
    struct pollfd stdin_poll = { .fd = STDIN_FILENO
            , .events = POLLIN | POLLRDBAND | POLLRDNORM | POLLPRI };

    int ev_offset = 0;

    bool entering_password = true;
    while (entering_password) {
        syslog(LOG_AUTH|LOG_ERR, "while");
        /* check password receiving from pam */
        if (poll(&stdin_poll, 1, 0) == 1) {
            int finish_flag;
            if (read(STDIN_FILENO, &finish_flag, sizeof(int)) == -1) {
                syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
                retval = PAM_AUTH_ERR;
            }
            syslog(LOG_AUTH|LOG_ERR, "helper: finish password");
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
        else if(rv > 0) { /* there was data to read */
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
                if (debug) {
                    syslog(LOG_AUTH | LOG_INFO, "helper: user %s Event: time %ld.%06ld, %s (%d)", user,
                           ev[i].time.tv_sec,
                           ev[i].time.tv_usec, evval[ev[i].value], (int) ev[i].code);
                }
            }
        }
    }
    long int last_press_time_sec = 0;
    long int last_press_time_usec = 0;

    double *time_features = malloc(num_actions * sizeof(double));
    int *correct_keycodes = malloc(num_actions * sizeof(int));
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
                    return PAM_SYSTEM_ERR;
                }
                time_features[features_num] = flight;
                features_num++;
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
                        return PAM_SYSTEM_ERR;
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

    /* read from file */
    char user_file_path[100] = "/etc/keystroke-pam/";
    strcat(user_file_path, user);
    FILE *f = fopen(user_file_path,"r");
    if ( !f ) {
        syslog (LOG_AUTH|LOG_ERR, "Error: Unable to open input file.\n");
        return PAM_SYSTEM_ERR;
    }
    syslog (LOG_AUTH|LOG_ERR, "open file. %s", user_file_path);
    int rows, cols;
    double norm_score;
    if ( fscanf(f,"%lf%d%d", &norm_score, &rows, &cols) != 3 ) {
        syslog (LOG_AUTH|LOG_ERR, "Error: wrong file format.\n");
        return PAM_SYSTEM_ERR;
    }
    syslog (LOG_AUTH|LOG_ERR, "open file. %s", user_file_path);
    if (cols != features_num) {
        syslog (LOG_AUTH|LOG_ERR, "features_num is not equal: cols=%d, features_num=%d", cols, features_num);
        int res = PAM_AUTH_ERR;
        if (write(STDOUT_FILENO, &res, sizeof(int)) == -1) {
            syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
            retval = PAM_AUTH_ERR;
        }
        return res;
    }

    syslog (LOG_AUTH|LOG_INFO, "norm: %lf\n", norm_score);
    syslog (LOG_AUTH|LOG_INFO, "rows, cols %d, %d\n", rows, cols);
    double *passwords_features;
    double *passwords_features_copy;
    bool find_EOF = false;
    passwords_features = malloc(rows * cols * sizeof(double));
    passwords_features_copy = malloc(rows * cols * sizeof(double));
    for (int i = 0; i < rows; i++) {
        syslog (LOG_AUTH|LOG_INFO, "read row %d\n", i);
        for (int j = 0; j < cols; j++) {
            syslog (LOG_AUTH|LOG_INFO, "read feature %d\n", j);
            double feature;
            if (fscanf(f,"%lf", &feature) == EOF) {
                find_EOF = true;
                syslog (LOG_AUTH|LOG_INFO, "find EOF");
            } else {
                passwords_features[i * cols + j] = passwords_features_copy[i * cols + j] = feature;
            }
        }
    }
    if (find_EOF) {
        syslog(LOG_AUTH|LOG_ERR, "corrupted format");
        return PAM_SYSTEM_ERR;
    }
    fclose(f);
    double *time_features_copy = malloc(features_num * sizeof(double));
    for (int i = 0; i < features_num; i++) {
        time_features_copy[i] = time_features[i];
    }
    double result_score;
    result_score = score_keystrokes(passwords_features, rows,
                     features_num, time_features, &norm_score);
    if (debug) {
        syslog(LOG_AUTH | LOG_INFO, "result score: %f", result_score);
    }

    free(passwords_features);
    free(correct_keycodes);
    free(time_features);
    close(fd);

    if (result_score >= score) {
        char user_file_path_tmp[100];
        strcpy(user_file_path_tmp, user_file_path);
        strcat(user_file_path_tmp, "_tmp");
        int fd = open(user_file_path_tmp, O_WRONLY | O_CREAT, 00600);
        if (fd < 0) {
            syslog(LOG_AUTH | LOG_INFO, "temp file creation error");
        };
        dprintf(fd, "%f\n%d %d\n", norm_score, rows + 1, cols);
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                dprintf(fd, "%.3f ", passwords_features_copy[i * cols + j]);
            }
            dprintf(fd, "\n");
        }
        for (int j = 0; j < cols; j++) {
            dprintf(fd, "%.3f ", time_features_copy[j]);
        }
        dprintf(fd, "\n");
        close(fd);
        free(time_features_copy);
        /* Delete original source file */
        remove(user_file_path);
        /* Rename temporary file as original file */
        rename(user_file_path_tmp, user_file_path);
        /* report to pam */
        int res = PAM_SUCCESS;
        if (write(STDOUT_FILENO, &res, sizeof(int)) == -1) {
            syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
            retval = PAM_AUTH_ERR;
        }
        return res;
    } else {
        free(time_features_copy);
        /* report to pam */
        int res = PAM_AUTH_ERR;
        if (write(STDOUT_FILENO, &res, sizeof(int)) == -1) {
            syslog(LOG_AUTH|LOG_ERR, "helper: cannot send message from helper");
            retval = PAM_AUTH_ERR;
        }
        return res;
    }
}
