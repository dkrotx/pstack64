#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* getopt_long */
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <stdlib.h>
#include <stdio.h>
#include <endian.h>
#include <sysexits.h>
#include <getopt.h>
#include <err.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

static void show_backtrace(pid_t pid, int nmax);
static void usage();
static const char *g_progname;


int main(int argc, char *argv[])
{
    int pid, nmax = -1;
    g_progname = argv[0];

    while(1) {
        int c;
        static struct option long_opts[] = {
            {"max-depth", required_argument, 0,  'm' },
            {"help",      no_argument, 0,  'h' }
        };

        c = getopt_long(argc, argv, "m:h", long_opts, NULL);
        if (c == -1) {
            argc -= optind;
            argv += optind;
            break;
        }

        switch(c) {
            case 'm': nmax = atoi(optarg); break;
            default: usage();
        }
    }

    if (argc != 1) {
        usage();
    }

    pid = atoi(argv[0]);
    show_backtrace(pid, nmax);
    return 0;
}


int wait4stop(pid_t pid)
{
    int status;
    
    do {
        if (waitpid(pid, &status, 0) == -1 || 
            WIFEXITED(status) || WIFSIGNALED(status)) {
            return 0;
        }
    } while( !WIFSTOPPED(status) );

    return 1;
}

void show_backtrace(pid_t pid, int nmax)
{
    unw_cursor_t resume_cursor;
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip, sp;
    unw_addr_space_t addr_space;
    void *rctx; /* arg for libunwind callbacks */

    addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!addr_space)
        err(EXIT_FAILURE, "Failed to create address space");

    unw_getcontext(&uc);
   
    if ( -1 == ptrace(PTRACE_ATTACH, pid, NULL, NULL) )
        err(1, "ptrace(%d) failed", pid);

    if (!wait4stop(pid))
        err(1, "wait SIGSTOP of ptrace failed");

    rctx = _UPT_create(pid);
    if (!rctx)
        err(EXIT_FAILURE, "Failed to create context with _UPT_create");

    if (unw_init_remote(&cursor, addr_space, rctx))
        err(1, "unw_init_remote failed");

    resume_cursor = cursor;

    do {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        printf ("0x%lx\n", ip);
    } while (--nmax && unw_step(&cursor) > 0);

    /* resume execution at top frame */
    _UPT_resume(addr_space, &resume_cursor, rctx);
    _UPT_destroy(rctx);
}

void usage()
{
    fprintf(stderr, "Usage: %s [-m|--max-depth N] [-h] pid\n", g_progname);
    fprintf(stderr, "\t-h|--help: show this help\n"
                    "\t-m|--max-depth N: unwind no more than N frames\n\n");
    exit(EX_USAGE);
}
