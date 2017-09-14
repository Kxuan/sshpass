/*  This file is part of "sshpass", a tool for batch running password ssh authentication
 *  Copyright (C) 2006, 2015 Lingnu Open Source Consulting Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version, provided that it was accepted by
 *  Lingnu Open Source Consulting Ltd. as an acceptable license for its
 *  projects. Consult http://www.lingnu.com/licenses.html
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H

#include "config.h"

#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <fcntl.h>

#if HAVE_TERMIOS_H
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <pty.h>

enum program_return_codes
{
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
};
typedef enum
{
    QUESTION_HOST_KEY_CHANGED,
    QUESTION_HOST_KEY_VERIFY,
    QUESTION_PASSWORD,
    QUESTION_OTP,
    QUESTION_UNKNOWN
} question_type_t;
typedef struct
{
    question_type_t value;
    const char *match;
    int match_state;

    int (*fn)(int fd);
} remote_question_entity_t;

remote_question_entity_t all_questions[];

// Some systems don't define posix_openpt
#ifndef HAVE_POSIX_OPENPT
int
posix_openpt(int flags)
{
    return open("/dev/ptmx", flags);
}
#endif

int runprogram(int argc, char *argv[]);

typedef enum
{
    PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS
} password_type;
struct
{
    password_type pwtype;
    union
    {
        const char *filename;
        int fd;
        const char *password;
    } pwsrc;

    const char *otp_file;
    char *initial_command;
    int verbose;
} args;

static void show_help()
{
    printf("Usage: " PACKAGE_NAME " [-f|-d|-p|-e] -o <key_file> [-hV] command parameters\n"
               "   -f filename   Take password to use from file\n"
               "   -d number     Use number as file descriptor for getting password\n"
               "   -p password   Provide password as argument (security unwise)\n"
               "   -e            Password is passed as env-var \"SSHPASS\"\n"
               "   With no parameters - password will be taken from stdin\n\n"
               "   -o <key_file> The file which stores the key of otp\n"
               "   -P prompt     Which string should sshpass search for to detect a password prompt\n"
               "   -v            Be verbose about what you're doing\n"
               "   -h            Show help (this screen)\n"
               "   -V            Print version information\n"
               "At most one of -f, -d, -p or -e should be used\n");
}

// Parse the command line. Fill in the "args" global struct with the results. Return argv offset
// on success, and a negative number on failure
static int parse_options(int argc, char *argv[])
{
    int error = -1;
    int opt;

    // Set the default password source to stdin
    args.pwtype = PWT_STDIN;
    args.pwsrc.fd = 0;

#define VIRGIN_PWTYPE if( args.pwtype!=PWT_STDIN ) { \
    fprintf(stderr, "Conflicting password source\n"); \
    error=RETURN_CONFLICTING_ARGUMENTS; }

    while ((opt = getopt(argc, argv, "+f:d:p:P:heo:c:Vv")) != -1 && error == -1) {
        switch (opt) {
        case 'f':
            // Password should come from a file
            VIRGIN_PWTYPE;

            args.pwtype = PWT_FILE;
            args.pwsrc.filename = optarg;
            break;
        case 'd':
            // Password should come from an open file descriptor
            VIRGIN_PWTYPE;

            args.pwtype = PWT_FD;
            args.pwsrc.fd = atoi(optarg);
            break;
        case 'p':
            // Password is given on the command line
            VIRGIN_PWTYPE;

            args.pwtype = PWT_PASS;
            args.pwsrc.password = strdup(optarg);

            // Hide the original password from the command line
            {
                int i;

                for (i = 0; optarg[i] != '\0'; ++i)
                    optarg[i] = 'z';
            }
            break;
        case 'P':
            assert(all_questions[QUESTION_PASSWORD].value == QUESTION_PASSWORD);
            all_questions[QUESTION_PASSWORD].match = strdup(optarg); // FIXME memory leak
            break;
        case 'v':
            args.verbose++;
            break;
        case 'e':
            VIRGIN_PWTYPE;

            args.pwtype = PWT_PASS;
            args.pwsrc.password = getenv("SSHPASS");
            if (args.pwsrc.password == NULL) {
                fprintf(stderr, "sshpass: -e option given but SSHPASS environment variable not set\n");

                error = RETURN_INVALID_ARGUMENTS;
            }
            break;
        case 'o':
            args.otp_file = strdup(optarg);
            break;
        case 'c':
            args.initial_command = strdup(optarg);
            break;
        case 'h':
            error = RETURN_NOERROR;
            break;
        case 'V':
            printf("%s\n"
                       "(C) 2006-2011 Lingnu Open Source Consulting Ltd.\n"
                       "(C) 2015-2016 Shachar Shemesh\n"
                       "This program is free software, and can be distributed under the terms of the GPL\n"
                       "See the COPYING file for more information.\n"
                       "\n"
                       "Using \"%s\" as the default password prompt indicator.\n", PACKAGE_STRING, PASSWORD_PROMPT);
            exit(0);
            break;
        case '?':
        case ':':
        default:
            error = RETURN_INVALID_ARGUMENTS;
            break;
        }
    }

    if (error >= 0)
        return -(error + 1);
    else
        return optind;
}

int main(int argc, char *argv[])
{
    int opt_offset = parse_options(argc, argv);

    if (opt_offset < 0) {
        // There was some error
        show_help();

        return -(opt_offset + 1); // -1 becomes 0, -2 becomes 1 etc.
    }

    if (argc - opt_offset < 1) {
        show_help();

        return 0;
    }

    return runprogram(argc - opt_offset, argv + opt_offset);
}

int handleoutput(int fd);

/* Global variables so that this information be shared with the signal handler */
static int ourtty; // Our own tty
static int masterpt;

void window_resize_handler(int signum);

void sigchld_handler(int signum);

int runprogram(int argc, char *argv[])
{
    struct winsize ttysize; // The size of our tty

    // We need to interrupt a select with a SIGCHLD. In order to do so, we need a SIGCHLD handler
    signal(SIGCHLD, sigchld_handler);

    // Create a pseudo terminal for our process
    masterpt = posix_openpt(O_RDWR);

    if (masterpt == -1) {
        perror("Failed to get a pseudo terminal");

        return RETURN_RUNTIME_ERROR;
    }

    fcntl(masterpt, F_SETFL, O_NONBLOCK);

    if (grantpt(masterpt) != 0) {
        perror("Failed to change pseudo terminal's permission");

        return RETURN_RUNTIME_ERROR;
    }
    if (unlockpt(masterpt) != 0) {
        perror("Failed to unlock pseudo terminal");

        return RETURN_RUNTIME_ERROR;
    }

    ourtty = open("/dev/tty", 0);
    if (ourtty != -1 && ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0) {
        signal(SIGWINCH, window_resize_handler);

        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    }

    const char *name = ptsname(masterpt);
    int slavept;
    /*
       Comment no. 3.14159

       This comment documents the history of code.

       We need to open the slavept inside the child process, after "setsid", so that it becomes the controlling
       TTY for the process. We do not, otherwise, need the file descriptor open. The original approach was to
       close the fd immediately after, as it is no longer needed.

       It turns out that (at least) the Linux kernel considers a master ptty fd that has no open slave fds
       to be unused, and causes "select" to return with "error on fd". The subsequent read would fail, causing us
       to go into an infinite loop. This is a bug in the kernel, as the fact that a master ptty fd has no slaves
       is not a permenant problem. As long as processes exist that have the slave end as their controlling TTYs,
       new slave fds can be created by opening /dev/tty, which is exactly what ssh is, in fact, doing.

       Our attempt at solving this problem, then, was to have the child process not close its end of the slave
       ptty fd. We do, essentially, leak this fd, but this was a small price to pay. This worked great up until
       openssh version 5.6.

       Openssh version 5.6 looks at all of its open file descriptors, and closes any that it does not know what
       they are for. While entirely within its prerogative, this breaks our fix, causing sshpass to either
       hang, or do the infinite loop again.

       Our solution is to keep the slave end open in both parent AND child, at least until the handshake is
       complete, at which point we no longer need to monitor the TTY anyways.
     */

    int childpid = fork();
    if (childpid == 0) {
        // Child

        // Detach us from the current TTY
        setsid();
        // This line makes the ptty our controlling tty. We do not otherwise need it open
        slavept = open(name, O_RDWR);
        close(slavept);

        close(masterpt);

        char **new_argv = malloc(sizeof(char *) * (argc + 1));

        int i;

        for (i = 0; i < argc; ++i) {
            new_argv[i] = argv[i];
        }

        new_argv[i] = NULL;

        execvp(new_argv[0], new_argv);

        perror("sshpass: Failed to run command");

        exit(RETURN_RUNTIME_ERROR);
    } else if (childpid < 0) {
        perror("sshpass: Failed to create child process");

        return RETURN_RUNTIME_ERROR;
    }

    // We are the parent
    slavept = open(name, O_RDWR | O_NOCTTY);

    int status = 0;
    int terminate = 0;
    pid_t wait_id;
    sigset_t sigmask, sigmask_select;

    // Set the signal mask during the select
    sigemptyset(&sigmask_select);

    // And during the regular run
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    sigprocmask(SIG_SETMASK, &sigmask, NULL);

    int ret;
    do {
        fd_set readfd;

        FD_ZERO(&readfd);
        FD_SET(masterpt, &readfd);

        int selret = pselect(masterpt + 1, &readfd, NULL, NULL, NULL, &sigmask_select);

        if (selret <= 0) {
            perror("pselect");
            continue;
        }

        if (!FD_ISSET(masterpt, &readfd))
            continue;

        ret = handleoutput(masterpt);
        if (ret == RETURN_PARSE_ERRROR) {
            ret = 0;
            continue;
        }
    } while (!ret &&
             (waitpid(childpid, &status, WNOHANG) == 0 ||
              (!WIFEXITED(status) && !WIFSIGNALED(status))
             ));

    close(masterpt);
    close(slavept);
    if (ret > 0)
        return ret;
    else if (WIFEXITED(status))
        return WEXITSTATUS(status);
    else
        return 255;
}

int match(const char *reference, const char *buffer, ssize_t bufsize, int *pstate);

remote_question_entity_t *parse_output(const char *output, uint size)
{
    remote_question_entity_t *entity = all_questions;
    int state;
    while (entity->fn) {
        state = match(entity->match, output, size, &entity->match_state);
        if (state) {
            entity->match_state = 0;
            return entity;
        }
        entity++;
    }
    return NULL;
}

int handleoutput(int fd)
{
    remote_question_entity_t *question;
    // We are looking for the string
    char buffer[256];

    ssize_t numread = read(fd, buffer, sizeof(buffer) - 1);
    if (numread < 0)
        return -1;
    buffer[numread] = '\0';
    if (args.verbose) {
        fprintf(stderr, "SSHPASS read: %s\n", buffer);
    }
    question = parse_output(buffer, (uint) numread);
    if (!question) {
        if (args.verbose)
            fprintf(stderr, "Unknown output %s\n", buffer);
        return RETURN_PARSE_ERRROR;
    }

    return question->fn(fd);
}

int match(const char *reference, const char *buffer, ssize_t bufsize, int *pstate)
{
    // This is a highly simplisic implementation. It's good enough for matching "Password: ", though. No, its not enough.
    int i;
    int state = pstate ? *pstate : 0;
    for (i = 0; reference[state] != '\0' && i < bufsize; ++i) {
        if (reference[state] == buffer[i])
            state++;
        else {
            state = 0;
            if (reference[state] == buffer[i])
                state++;
        }
    }

    if (pstate)
        *pstate = state;

    return state;
}

void write_pass_fd(int srcfd, int dstfd);

void write_pass(int fd)
{
    switch (args.pwtype) {
    case PWT_STDIN:
        write_pass_fd(STDIN_FILENO, fd);
        break;
    case PWT_FD:
        write_pass_fd(args.pwsrc.fd, fd);
        break;
    case PWT_FILE: {
        int srcfd = open(args.pwsrc.filename, O_RDONLY);
        if (srcfd != -1) {
            write_pass_fd(srcfd, fd);
            close(srcfd);
        }
    }
        break;
    case PWT_PASS:
        write(fd, args.pwsrc.password, strlen(args.pwsrc.password));
        write(fd, "\n", 1);
        break;
    }
}

void write_pass_fd(int srcfd, int dstfd)
{

    int done = 0;

    while (!done) {
        char buffer[40];
        int i;
        int numread = (int) read(srcfd, buffer, sizeof(buffer));
        done = (numread < 1);
        for (i = 0; i < numread && !done; ++i) {
            if (buffer[i] != '\n')
                write(dstfd, buffer + i, 1);
            else
                done = 1;
        }
    }

    write(dstfd, "\n", 1);
}

void window_resize_handler(int signum)
{
    struct winsize ttysize; // The size of our tty

    if (ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0)
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
}

// Do nothing handler - makes sure the select will terminate if the signal arrives, though.
void sigchld_handler(int signum)
{
}

int handle_host_key_changed(int fd)
{
    if (args.verbose)
        fprintf(stderr, "SSHPASS detected host identification changed. Exiting.\n");
    return RETURN_HOST_KEY_CHANGED;
}

int handle_host_key_verify(int fd)
{

    if (args.verbose)
        fprintf(stderr, "SSHPASS detected host authentication prompt. Exiting.\n");
    return RETURN_HOST_KEY_UNKNOWN;
}

int handle_password(int fd)
{
    static int prevmatch = 0; // If the "password" prompt is repeated, we have the wrong password.
    if (prevmatch) {
        // Wrong password - terminate with proper error code
        if (args.verbose)
            fprintf(stderr, "SSHPASS detected prompt, again. Wrong password. Terminating.\n");
        return RETURN_INCORRECT_PASSWORD;
    }

    if (args.verbose)
        fprintf(stderr, "SSHPASS detected prompt. Sending password.\n");
    write_pass(fd);
    prevmatch = 1;
    return RETURN_NOERROR;
}

void otp(const char *otp_secret, size_t secret_size, char code[7])
{
    time_t tick;
    uint32_t tick_normal;
    uint8_t message[8] = {0};
    uint8_t sha_digest[SHA_DIGEST_LENGTH];
    uint digest_len = sizeof(sha_digest);
    int offset;
    uint32_t number;

    tick = time(NULL) / 30;
    if (tick > UINT32_MAX) {
        fprintf(stderr, "Excited!!\n");
        abort();
    }

    tick_normal = htonl((uint32_t) tick);
    memcpy(message + 4, &tick_normal, 4);

    HMAC(EVP_sha1(), otp_secret, secret_size, message, sizeof(message), sha_digest, &digest_len);

    offset = sha_digest[sizeof(sha_digest) - 1] & 0xf;
    number = (ntohl(*(uint32_t *) (sha_digest + offset)) & 0x7fffffff) % 1000000;
    snprintf(code, 7, "%06d", number);
}

int read_otp_key(const char *filename, char *key_buf, size_t max_key_size)
{
    int length = -1;
    int fd;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        if (args.verbose) {
            perror("open otp file");
        }
        return -1;
    }

    length = (int) read(fd, key_buf, max_key_size);

    if (length < 0) {
        if (args.verbose) {
            perror("read otp file");
        }
    }

    close(fd);
    return length;
}

int handle_otp(int fd)
{
    static int try_times = 2;

    if (!args.otp_file) {
        if (args.verbose)
            fprintf(stderr, "SSHPASS detected OTP prompt, but no OTP key given. Terminating.\n");
        return RETURN_INCORRECT_PASSWORD;
    }

    if (!try_times) {
        if (args.verbose)
            fprintf(stderr, "SSHPASS detected OTP prompt, again. Wrong OTP key. Terminating.\n");
        return RETURN_INCORRECT_PASSWORD;
    }

    --try_times;

    if (args.verbose)
        fprintf(stderr, "SSHPASS detected OTP prompt. Sending OTP.\n");

    int otp_key_size;
    char otp_key[4096], otp_code[7];

    otp_key_size = read_otp_key(args.otp_file, otp_key, sizeof(otp_key));
    if (otp_key_size < 0) {
        return RETURN_INCORRECT_PASSWORD;
    }

    otp(otp_key, otp_key_size, otp_code);
    write(fd, otp_code, sizeof(otp_code) - 1);
    write(fd, "\n", 1);

    return RETURN_NOERROR;
}

// Please keep the same order as question_type_t.
remote_question_entity_t all_questions[] = {
    // The remote identification changed error is sent to stderr, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    {QUESTION_HOST_KEY_CHANGED, "REMOTE HOST IDENTIFICATION HAS CHANGED", 0, handle_host_key_changed},
    {QUESTION_HOST_KEY_VERIFY,  "The authenticity of host ",              0, handle_host_key_verify},
    {QUESTION_PASSWORD, PASSWORD_PROMPT,                                  0, handle_password},
    {QUESTION_OTP,      OTP_PROMPT,                                       0, handle_otp},
    {0,                 NULL,                                             0, NULL}
};