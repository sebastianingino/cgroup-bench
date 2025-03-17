#define _GNU_SOURCE

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a > _b ? _a : _b;                                                         \
  })

#define STACK_SIZE 65536
#define INT_STR_SIZE 12
#define CGROUP_DIR "/sys/fs/cgroup/container/"
#define ROOT_DIR "/home/ubuntu/cgroup-bench/root/"

#define CPU_PERCENTAGE 0.2f
// 64MB limit
#define MEM_LIMIT "67108864"

#define NUM_ITERS 128

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

void *stack() {
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

void write_cgroup_rule(const char *path, const char *value) {
  DEBUG_PRINT("Writing to cgroup");
  int fd = open(path, O_WRONLY | O_APPEND | O_CREAT);
  DEBUG_PRINT(" with fd %d.\n", fd);
  size_t write_len = write(fd, value, strlen(value));
  // printf("Wrote %zu bytes.\n", write_len);
  close(fd);
}

void set_cgroup_limits(pid_t pid) {
  mkdir(CGROUP_DIR, S_IRUSR | S_IWUSR);
  printf("Constructed cgroup dirs.\n");

  char pid_str[INT_STR_SIZE];
  sprintf(pid_str, "%d", pid);
  DEBUG_PRINT("Child process has pid %d\n", pid);

  write_cgroup_rule(CGROUP_DIR "cgroup.procs", pid_str);
  DEBUG_PRINT("Wrote cgroup values.\n");

  write_cgroup_rule(CGROUP_DIR "memory.limit_in_bytes", MEM_LIMIT);
}

uint8_t add_two(uint8_t v1, uint8_t v2) { return v1 + v2; }

int container(void *shm) {
  DEBUG_PRINT("Beginning container.\n");

  clearenv();
  chroot(ROOT_DIR);
  chdir("/");

  // DIR *d;
  // struct dirent *dir;
  // d = opendir(".");
  // if (d) {
  //   while ((dir = readdir(d)) != NULL) {
  //     printf("%s\n", dir->d_name);
  //   }
  //   closedir(d);
  // }
  //

  // char *exec_args[] = {"/usr/bin/bash", NULL};
  // execv("/usr/bin/bash", exec_args);

  struct Args args = *(struct Args *)shm;
  struct Retval retval;
  retval.r1 = add_two(args.v1, args.v2);
  *(struct Retval *)shm = retval;

  DEBUG_PRINT("Ending container.\n");

  exit(0);
}

int main(int argc, char *argv[]) {
  srand(time(NULL));
  DEBUG_PRINT("Begin main.\n");

  // Begin

  for (size_t i = 0; i < NUM_ITERS; i++) {
    void *shm = new_shm();
    struct Args args = {.v1 = rand(), .v2 = rand()};
    *(struct Args *)shm = args;

    DEBUG_PRINT("Initialized shared memory.\n");

    pid_t pid =
        clone(container, stack(),
              CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                  CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWUSER | SIGCHLD,
              shm);
    int status = 0;
    waitpid(pid, &status, 0);
    DEBUG_PRINT("Container exited with status code %d\n", status);

    struct Retval retval = *(struct Retval *)shm;
    assert(retval.r1 == (uint8_t)(args.v1 + args.v2));
    DEBUG_PRINT("Function returned %d\n", retval.r1);
  }
  // End

  return status;
}
