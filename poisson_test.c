#define _GNU_SOURCE

#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wait.h>

#define STACK_SIZE 1024 // 1KB
#define ROOT_DIR "/home/ubuntu/cgroup-bench/root/"

#define MAX(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a > _b ? _a : _b;                                                         \
  })

// #define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...)                                                       \
  do {                                                                         \
  } while (0)
#endif

struct Args {
  uint8_t v1;
  uint8_t v2;
};

struct Retval {
  uint8_t r1;
};

void *new_stack() {
  void *stack = malloc(STACK_SIZE);
  if (!stack) {
    fprintf(stderr, "Failed to allocate stack.\n");
    exit(-1);
  }
  return stack;
}

void *new_shm() {
  size_t size = MAX(sizeof(struct Args), sizeof(struct Retval));
  void *mmap_result = mmap(NULL, size, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  if (!mmap_result) {
    fprintf(stderr, "Failed to construct shared memory object.\n");
    exit(-1);
  }
  return mmap_result;
}

int container(void *shm) {
  DEBUG_PRINT("Beginning container.\n");

  clearenv();
  chroot(ROOT_DIR);
  chdir("/");

  struct Args args = *(struct Args *)shm;
  struct Retval retval;
  retval.r1 = add_two(args.v1, args.v2);
  *(struct Retval *)shm = retval;

  DEBUG_PRINT("Ending container.\n");

  return 0;
}

int execute_containerized(void *shm) {
  void *stack = new_stack();
  pid_t pid =
      clone(container, stack + STACK_SIZE,
            CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWUSER | SIGCHLD,
            shm);
  int status = 0;
  waitpid(pid, &status, 0);

  DEBUG_PRINT("Container exited with status code %d\n", status);
  free(stack);
  return status;
}
