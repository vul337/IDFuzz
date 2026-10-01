// Add to the same directory as afl-fuzz.c.
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdint.h>

#define SHMSIZE (1024)

/* Layout: [0] flag, [1] payload length, [2..] payload. The Python side reads
   a 256-byte window, so a payload can be at most 254 bytes. */
#define SHM_MSG_MAX (254)

/* How long the fuzzer waits for the NN to answer a query before giving up
   and falling back to normal mutation. Override with IDFUZZ_NN_TIMEOUT_MS. */
#define SHM_REPLY_TIMEOUT_MS (5000)

extern char *CPY_SHM;
extern int cpy_shmid;

uint8_t *shm_check(volatile uint8_t *buf); // Wait (bounded) until the fuzzer owns the shm, return a pointer to the payload.
void shm_spin_unlock(); // Set the first byte to 1, handing over the shm to Python.
int mywrite(char *input); // Send a message to Python if the shm is free right now; returns 0 if it is not.
int myread(char *out, size_t cap); // Wait (bounded) for Python's reply and copy it into out; returns 0 on hold/timeout.
void get_shm_cpy(int keyid); // Create and obtain the shared memory.
void delete_shm_cpy(); // Use shmctl to destroy the shared memory.
uint8_t shm_check_hold(volatile uint8_t *buf); // Check if the neural network is in training.
