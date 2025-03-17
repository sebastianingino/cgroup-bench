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

#define STACK_SIZE 1024 // 1KB
#define INT_STR_SIZE 12
#define CGROUP_DIR "/sys/fs/cgroup/container/"
#define ROOT_DIR "/home/ubuntu/cgroup-bench/root/"

#define CPU_PERCENTAGE 0.2f
#define MEM_LIMIT "67108864" // 64MB

#define NUM_ITERS 50
#define NUM_EXPS 8

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

void write_cgroup_rule(const char *path, const char *value) {
  DEBUG_PRINT("Writing to cgroup");
  int fd = open(path, O_WRONLY | O_APPEND | O_CREAT);
  DEBUG_PRINT(" with fd %d.\n", fd);
  size_t write_len = write(fd, value, strlen(value));
  DEBUG_PRINT("Wrote %zu bytes.\n", write_len);
  close(fd);
}

void set_cgroup_limits(pid_t pid) {
  mkdir(CGROUP_DIR, S_IRUSR | S_IWUSR);
  DEBUG_PRINT("Constructed cgroup dirs.\n");

  char pid_str[INT_STR_SIZE];
  sprintf(pid_str, "%d", pid);
  DEBUG_PRINT("Child process has pid %d\n", pid);

  write_cgroup_rule(CGROUP_DIR "cgroup.procs", pid_str);
  DEBUG_PRINT("Wrote cgroup values.\n");

  write_cgroup_rule(CGROUP_DIR "memory.limit_in_bytes", MEM_LIMIT);
}

uint8_t add_two(uint8_t v1, uint8_t v2) { return v1 + v2; }

int cloned_process(void *shm) {
  struct Args args = *(struct Args *)shm;
  struct Retval retval;
  retval.r1 = add_two(args.v1, args.v2);
  *(struct Retval *)shm = retval;

  return 0;
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

int test_basic_clone(void *shm) {
  void *stack = new_stack();
  pid_t pid = clone(cloned_process, stack + STACK_SIZE, SIGCHLD, shm);
  int status = 0;
  waitpid(pid, &status, 0);

  DEBUG_PRINT("Clone exited with status code %d\n", status);
  free(stack);
  return status;
}

int test_clone_reused_stack(void *shm, void *stack) {
  pid_t pid = clone(cloned_process, stack + STACK_SIZE, SIGCHLD, shm);
  int status = 0;
  waitpid(pid, &status, 0);

  DEBUG_PRINT("Clone exited with status code %d\n", status);
  return status;
}

int test_clone_cgroup(void *shm) {
  void *stack = new_stack();
  pid_t pid = clone(cloned_process, stack + STACK_SIZE, SIGCHLD | CLONE_NEWCGROUP, shm);
  int status = 0;
  waitpid(pid, &status, 0);

  DEBUG_PRINT("Clone exited with status code %d\n", status);
  free(stack);
  return status;
}

int test_container(void *shm) {
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

int main(int argc, char *argv[]) {
  srand(time(NULL));
  DEBUG_PRINT("Begin main.\n");

  // Initialize arguments
  void *shm = new_shm();
  struct Args args = {.v1 = rand(), .v2 = rand()};
  *(struct Args *)shm = args;
  DEBUG_PRINT("Initialized args.\n");

  // Assert that the basic add function works
  test_basic_clone(shm);
  struct Retval retval = *(struct Retval *)shm;
  assert(retval.r1 == add_two(args.v1, args.v2));
  *(struct Args *)shm = args;

  test_clone_cgroup(shm);
  retval = *(struct Retval *)shm;
  assert(retval.r1 == add_two(args.v1, args.v2));
  *(struct Args *)shm = args;

  test_container(shm);
  retval = *(struct Retval *)shm;
  assert(retval.r1 == add_two(args.v1, args.v2));
  *(struct Args *)shm = args;

  // Time the basic add function
  struct timespec tstart = {0, 0}, tend = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  for (size_t i = 0; i < NUM_ITERS; i++) {
    add_two(args.v1, args.v2);
  }
  clock_gettime(CLOCK_MONOTONIC, &tend);
  // Time in nanoseconds
  double elapsed = ((double)tend.tv_sec * 1e9 + (double)tend.tv_nsec) -
                   ((double)tstart.tv_sec * 1e9 + (double)tstart.tv_nsec);
  printf("Raw function: Add takes %f ns\n", elapsed / NUM_ITERS);

  // Time the clone call
  for (size_t i = 0, j = 128; i < NUM_EXPS; i++, j *= 2) {
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    for (size_t k = 0; k < j; k++) {
      test_basic_clone(shm);
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    // Time in nanoseconds
    elapsed = ((double)tend.tv_sec * 1e9 + (double)tend.tv_nsec) -
              ((double)tstart.tv_sec * 1e9 + (double)tstart.tv_nsec);
    printf("Clone: Add takes %f ns, %ld iterations\n", elapsed / j, j);
  }

  // Time the container
  for (size_t i = 0, j = 128; i < NUM_EXPS; i++, j *= 2) {
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    for (size_t k = 0; k < j; k++) {
      test_container(shm);
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    // Time in nanoseconds
    elapsed = ((double)tend.tv_sec * 1e9 + (double)tend.tv_nsec) -
              ((double)tstart.tv_sec * 1e9 + (double)tstart.tv_nsec);
    printf("Container: Add takes %f ns, %ld iterations\n", elapsed / j, j);
  }

  // Time the clone call with stack reuse
  void *stack = new_stack();
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  for (size_t i = 0; i < NUM_ITERS; i++) {
    test_clone_reused_stack(shm, stack);
  }
  free(stack);
  clock_gettime(CLOCK_MONOTONIC, &tend);
  // Time in nanoseconds
  elapsed = ((double)tend.tv_sec * 1e9 + (double)tend.tv_nsec) -
            ((double)tstart.tv_sec * 1e9 + (double)tstart.tv_nsec);
  printf("Clone + Stack Reuse: Add takes %f ns\n", elapsed / NUM_ITERS);

  // best case w/o stack reuse
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  for (size_t i = 0; i < NUM_ITERS; i++) {
    test_clone_cgroup(shm);
  }
  clock_gettime(CLOCK_MONOTONIC, &tend);
  // Time in nanoseconds
  elapsed = ((double)tend.tv_sec * 1e9 + (double)tend.tv_nsec) -
            ((double)tstart.tv_sec * 1e9 + (double)tstart.tv_nsec);
  printf("Clone + new cgroup: Add takes %f ns\n", elapsed / NUM_ITERS);

  // End
  if (munmap(shm, sizeof(struct Args)) == -1) {
    fprintf(stderr, "Failed to unmap shared memory.\n");
    exit(-1);
  }

  return 0;
}
