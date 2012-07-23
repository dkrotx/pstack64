#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <err.h>
#include <libunwind-ptrace.h>
#include <stdlib.h>
#include <libunwind.h>
#include <endian.h>
#include <sysexits.h>
#include <stdio.h>

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

void show_backtrace(pid_t pid)
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
    } while (unw_step(&cursor) > 0);

    _UPT_resume(addr_space, &resume_cursor, rctx);
    _UPT_destroy(rctx);
}

int main(int argc, char *argv[])
{
    int pid;

    if (argc < 2) {
        errx(EX_USAGE, "Usage: %s pid", argv[0]);
    }

    pid = atoi(argv[1]);
    show_backtrace(pid);
    return EXIT_SUCCESS;
}
