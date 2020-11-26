#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

#define PAM_DEBUG 1

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
// #include "support.h"

// # define WEXITSTATUS(stat_val) ((unsigned int) (stat_val) >> 8)

#define AUTH_RETURN						\
do {									\
	D(("recording return code for next time [%d]",		\
				retval));			\
	*ret_data = retval;					\
	pam_set_data(pamh, "unix_setcred_return",		\
			 (void *) ret_data, setcred_free);	\
	D(("done. [%s]", pam_strerror(pamh, retval)));		\
	return retval;						\
} while (0)

static void
setcred_free (pam_handle_t *pamh, void *ptr, int err)
{
    if (ptr)
        free (ptr);
}

#define BINARY_HELPER "/home/alexey/Documents/keystroke-pam/binary_helper"

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval, *ret_data = NULL;
    const char *name;
    const char *password;

    D(("called."));

    /* Get a few bytes so we can pass our return value to
	   pam_sm_setcred() and pam_sm_acct_mgmt(). */
    ret_data = malloc(sizeof(int));
    if (!ret_data) {
        D(("cannot malloc ret_data"));
        pam_syslog(pamh, LOG_CRIT,
                   "pam_unix_auth: cannot allocate ret_data");
        return PAM_BUF_ERR;
    }

    /* get the username */

    retval = pam_get_user(pamh, &name, NULL);
    if (retval == PAM_SUCCESS) {
        /*
         * Various libraries at various times have had bugs related to
         * '+' or '-' as the first character of a user name. Don't
         * allow this characters here.
         */
        if (name[0] == '-' || name[0] == '+') {
            pam_syslog(pamh, LOG_NOTICE, "bad username [%s]", name);
            retval = PAM_USER_UNKNOWN;
            AUTH_RETURN;
        }
//        if (on(UNIX_DEBUG, ctrl))
//            pam_syslog(pamh, LOG_DEBUG, "username [%s] obtained", name);
    } else {
        if (retval == PAM_CONV_AGAIN) {
            D(("pam_get_user/conv() function is not ready yet"));
            /* it is safe to resume this function so we translate this
             * retval to the value that indicates we're happy to resume.
             */
            retval = PAM_INCOMPLETE;
        }
//        else if (on(UNIX_DEBUG, ctrl)) {
//            pam_syslog(pamh, LOG_DEBUG, "could not obtain username");
//        }
        AUTH_RETURN;
    }

    const struct pam_conv *conv;
    struct pam_message msg[1];
    const struct pam_message *pmsg[1];
    struct pam_response *resp = NULL;

    unsigned num_msg = 1;
    pmsg[0] = &msg[0];

    /* get conv function */
    retval = pam_get_item(pamh, PAM_CONV, (const void **) (char *) &conv);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_DEBUG, "no conversation function");
        return retval;
    }

    msg[0].msg_style = PAM_TEXT_INFO;
    msg[0].msg = "keystroke pam";

    /* set initial message */
    retval = conv->conv(num_msg, pmsg, &resp, conv->appdata_ptr);
    pam_syslog(pamh, LOG_DEBUG, "before fork");

    /* create pipe for passing password to helper */
    int fd_to_helper[2];
    if (pipe(fd_to_helper) != 0) {
        pam_syslog(pamh, LOG_DEBUG, "could not make pipe");
        return PAM_AUTH_ERR;
    }

    /* create pipe for receiving ready message from helper */
    int fd_from_helper[2];
    if (pipe(fd_from_helper) != 0) {
        pam_syslog(pamh, LOG_DEBUG, "could not make pipe");
        return PAM_AUTH_ERR;
    }

    pid_t pid;

    struct sigaction newsa, oldsa;

//    if (off(UNIX_NOREAP, ctrl))
    if (1) {
        /*
         * This code arranges that the demise of the child does not cause
         * the application to receive a signal it is not expecting - which
         * may kill the application or worse.
         *
         * The "noreap" module argument is provided so that the admin can
         * override this behavior.
         */
        memset(&newsa, '\0', sizeof(newsa));
        newsa.sa_handler = SIG_DFL;
        sigaction(SIGCHLD, &newsa, &oldsa);
    }

    /* fork */
    pid = fork();
    if (pid == (pid_t) 0) {
        pam_syslog(pamh, LOG_DEBUG, "fork: child");
        static char *envp[] = {NULL};
        const char *args[] = {NULL, NULL, NULL, NULL};
        /* This is the child process.
          Close other end first. */
        close(fd_to_helper[1]);

        if (dup2(fd_to_helper[0], STDIN_FILENO) != STDIN_FILENO) {
            pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdin");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }

        close(fd_from_helper[0]);

        if (dup2(fd_from_helper[1], STDOUT_FILENO) != STDOUT_FILENO) {
            pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdout");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }
        /* exec binary helper */
        args[0] = BINARY_HELPER;
        args[1] = name;

        pam_syslog(pamh, LOG_DEBUG, "run binary");
        execve(BINARY_HELPER, (char *const *) args, envp);

        /* should not get here: exit with error */
        pam_syslog(pamh, LOG_DEBUG, "helper binary is not available");
        _exit(PAM_AUTHINFO_UNAVAIL);
    } else if (pid < (pid_t) 0) {
        /* The fork failed. */
        D(("fork failed"));
        close(fd_to_helper[0]);
        close(fd_to_helper[1]);
        close(fd_from_helper[0]);
        close(fd_from_helper[1]);
        retval = PAM_AUTH_ERR;
    } else {
        /* This is the parent process.
           Close other end first. */
        pam_syslog(pamh, LOG_DEBUG, "Fork: parent");

        close(fd_to_helper[0]); // close read end
        close(fd_from_helper[1]); // close write end


        msg[0].msg_style = PAM_TEXT_INFO;
        msg[0].msg = "Your keystroke dynamics will be checked while password input!";

        char message_from_helper[10];
        if (read(fd_from_helper[0], message_from_helper, 10) == -1) {
            pam_syslog(pamh, LOG_DEBUG, "Cannot receive message from helper");
            retval = PAM_AUTH_ERR;
        } else {
            pam_syslog(pamh, LOG_DEBUG, "message from helper: %s", message_from_helper);
        }
        close(fd_from_helper[0]);

        retval = conv->conv(num_msg, pmsg, &resp, conv->appdata_ptr);
        pam_syslog(pamh, LOG_DEBUG, "show note");

        int rc = 0;
        const char *password;
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
        pam_syslog(pamh, LOG_DEBUG, "password=%s\n", password);
        int len = strlen(password);
        if (write(fd_to_helper[1], password, len) == -1) {
            pam_syslog(pamh, LOG_DEBUG, "Cannot send password to helper");
            retval = PAM_AUTH_ERR;
        }
        password = NULL;
        pam_syslog(pamh, LOG_DEBUG, "password written\n");
        close(fd_to_helper[1]);

        while ((rc = waitpid(pid, &retval, 0)) < 0 && errno == EINTR);
        if (rc < 0) {
            pam_syslog(pamh, LOG_DEBUG, "unix_chkpwd waitpid returned ");
            retval = PAM_AUTH_ERR;
        } else if (!WIFEXITED(retval)) {
            pam_syslog(pamh, LOG_DEBUG, "unix_chkpwd abnormal exit:");
            retval = PAM_AUTH_ERR;
        } else {
            retval = WEXITSTATUS(retval);
        }
        return retval;
    }

}

int
pam_sm_setcred (pam_handle_t *pamh, int flags,
                int argc, const char **argv)
{
    int retval;
    retval = PAM_SUCCESS;
    return retval;
}