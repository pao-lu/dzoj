#define _GNU_SOURCE
#include <errno.h>             // for errno
#include <grp.h>               // for setgroups, gid_t
#include <linux/audit.h>       // for AUDIT_ARCH_X86_64
#include <linux/bpf_common.h>  // for BPF_K, BPF_JEQ, BPF_JMP, BPF_ABS, BPF_LD
#include <linux/filter.h>      // for BPF_STMT, BPF_JUMP, sock_filter, sock_...
#include <linux/seccomp.h>     // for seccomp_data, SECCOMP_RET_KILL_PROCESS
#include <stddef.h>            // for offsetof
#include <stdint.h>            // for uint32_t
#include <stdio.h>             // for perror, puts
#include <sys/prctl.h>         // for prctl, PR_SET_DUMPABLE, PR_SET_NO_NEW_...
#include <syscall.h>           // for SYS_execve, SYS_execveat, SYS_fork
#include <unistd.h>            // for chdir, chroot, getegid, geteuid, getgid

int go_simple_jail(uint32_t cookie, uint32_t uid, uint32_t gid,
                   const char *chroot_path) {
  int err;
#ifdef __i386__
#warning not tested
  struct sock_filter filter[] = {
      // [0] seccomp_data.arch -> A
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_vfork, 6, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fork, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 2),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               (offsetof(struct seccomp_data, args) + 8 * 3)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, cookie, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };
#elif defined(__x86_64__)
  struct sock_filter filter[] = {
      // [0] seccomp_data.arch -> A
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, (__X32_SYSCALL_BIT - 1)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_vfork, 6, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fork, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 2),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               (offsetof(struct seccomp_data, args) + 8 * 3)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, cookie, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };
#endif

  struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };

  gid_t groups[1] = {gid};

#define PERR_AND_RETURN(label) \
  do {                         \
    err = errno;               \
    perror(label);             \
    return err;                \
  } while (0)

  if (sethostname("sandbox", 7) == -1) PERR_AND_RETURN("sethostname");

  if ((prctl(PR_SET_DUMPABLE, 0)) == -1) return err;
  if ((prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) == -1) return err;
  if (chdir(chroot_path) == -1) PERR_AND_RETURN("chdir");
  if (chroot(".") == -1) PERR_AND_RETURN("chroot .");
  if (chdir("/") == -1) PERR_AND_RETURN("chdir /");

  if (setgid(gid) == -1) PERR_AND_RETURN("setgid");
  if (setgroups(1, groups) == -1) PERR_AND_RETURN("setgroups");

  if (setuid(uid) == -1) PERR_AND_RETURN("setuid");
  if (setsid() == -1) PERR_AND_RETURN("setsid");
  if (getuid() != uid || geteuid() != uid || getgid() != gid ||
      getegid() != gid) {
    puts("deroot failed");
    return -2;
  }

  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == -1) {
    perror("seccomp");
    return -2;
  }
  return 0;
}
