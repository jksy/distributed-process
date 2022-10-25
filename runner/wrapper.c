#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include "syscall_table.h"


void err_wrap(const int ret, const int success, const char *msg) {
    if (ret == success) {
        return;
    }

    printf("err_wrap() ret:%d, success:%d\n", ret, success);
    perror(msg);
    printf("exit failure");
    exit(EXIT_FAILURE);
}

// void print_ptrace_syscall_info(struct ptrace_syscall_info *info) {
//   switch(info->op) {
//     case PTRACE_SYSCALL_INFO_ENTRY:
//       printf("PTRACE_SYSCALL_INFO_ENTRY: info->entry.nr = %llx", info->entry.nr);
//       break;
//     case PTRACE_SYSCALL_INFO_EXIT:
//       printf("PTRACE_SYSCALL_INFO_EXIT: info->exit.rval = %llx", info->exit.rval);
//       break;
//     case PTRACE_SYSCALL_INFO_SECCOMP:
//       printf("PTRACE_SYSCALL_INFO_SECCOMP: info->seccomp.nr = %llx", info->seccomp.nr);
//       break;
//   }
// }
//
int read_string(pid_t pid, unsigned long addr, char *str, int len) {
  int i = 0;
  int ret = 0;
  char c = 0;

  for (i = 0; i < len; i++) {
    ret = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    if (ret == -1) {
      printf("read string failure\n");
      return -1;
    }

    c = (char)ret;
    if (c == '\0') {
      break;
    }

    str[i] = c;
  }

  printf("read string: %s(%d)\n", str, i);

  str[i] = '\0';
  return 0;
}

struct syscall_args {
  unsigned int no;
  unsigned long long arg0;
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long arg3;
  unsigned long long arg4;
  unsigned long long arg5;
  unsigned long long return_addr;
  unsigned long long rflags;
};

int convert_syscall_args(struct user_regs_struct *regs, struct syscall_args *args) {
  args->no = regs->orig_rax;
  args->arg0 = regs->rdi;
  args->arg1 = regs->rsi;
  args->arg2 = regs->rdx;
  args->arg3 = regs->r10;
  args->arg4 = regs->r8;
  args->arg5 = regs->r9;
  args->return_addr = regs->rcx;
  args->rflags = regs->r11;
  return 0;
}

int print_syscall_regs(pid_t pid, struct syscall_args *args) {
  char buf[256] = {0};
  switch(args->no) {
    case 0: // read
      read_string(pid, args->arg0, buf, 20);
      printf("read(\"%s...\", %llx, %llx)\n", buf, args->arg1, args->arg2);
      break;
    case 1: // write
      read_string(pid, args->arg0, buf, 20);
      printf("write(\"%s...\", %llx, %llx)\n", buf, args->arg1, args->arg2);
      break;
    case 257: // openat
      read_string(pid, args->arg1, buf, sizeof(buf));
      printf("openat(dirfd:%llx, \"%s\", %llx, %llx)\n", args->arg0, buf, args->arg2, args->arg3);
      break;
    case 262: // futimesat
      read_string(pid, args->arg1, buf, sizeof(buf));
      printf("futimesat(dirfd:%llx, pathname:%s, timeval:%llx)\n", args->arg0, buf, args->arg2);
  }
}


int main(int argc, char *argv[]) {
  if(argc < 2) {
    printf("Usage: %s <command>", argv[0]);
  }

  pid_t pid = fork();
  if(pid < 0) {
    printf("fork failed");
    return -1;
  }

  if(pid == 0) {
    // child
    err_wrap(ptrace(PTRACE_TRACEME, 0, 0, 0), 0, "ptrace-traceme");
    for(int i = 0; i < argc; i++) {
      printf("argv[%d] = %s\n", i, argv[i]);
    }
    // err_wrap(raise(SIGSTOP), 0, "raise-sigstop");
    execvp(argv[1], argv + 1);
  } else {
    int sts;
    printf("Child pid: %d\n", pid);

    struct ptrace_syscall_info info;
    struct user_regs_struct regs;
    struct syscall_args args;
    int status;

    printf("wait_pid\n");
    err_wrap(waitpid(pid, &sts, 0), pid, "waitpid");
    printf("ptrace-setoptions\n");
    err_wrap(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT), 0, "ptrace-setoptions");

    printf("while\n");
    while(1) {
      printf("ptrace-syscall\n");
      err_wrap(ptrace(PTRACE_SYSCALL, pid, 0, 0), 0, "ptrace-syscall");
      if(waitpid(pid, &status, 0) < 0) {
        printf("wait failed\n");
        return -1;
      }

      printf("syscall-entry-stop\n");
      // err_wrap(ptrace(PTRACE_GET_SYSCALL_INFO, pid, 0, &info), 0, "ptrace-get-syscall-info");
      // print_ptrace_syscall_info(&info);

      err_wrap(ptrace(PTRACE_GETREGS, pid, 0, &regs),  0, "ptrace-getregs");

      convert_syscall_args(&regs, &args);
      printf("==== name = %s[%u]\n", syscall_table[args.no], args.no);

      printf("Retrun address = %llx, saved rflags = %llx\n", regs.rcx, regs.r11);
      printf("arg0 = %llx\n", args.arg0);
      printf("arg1 = %llx\n", args.arg1);
      printf("arg2 = %llx\n", args.arg2);
      printf("arg3 = %llx\n", args.arg3);
      printf("arg4 = %llx\n", args.arg4);
      printf("arg5 = %llx\n", args.arg5);
      print_syscall_regs(pid, &args);
    }

  }

  return 0;
}

