// Add to the same directory as afl-fuzz.c.
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdint.h>

#define SHMSIZE (1024)
extern char *CPY_SHM;
extern int cpy_shmid;

uint8_t *shm_check(volatile uint8_t *buf); // Check if the fuzzer can write, return a pointer to the memory to be written.
void shm_spin_unlock(); // Set the first byte to 1, handing over the shm to Python.
int mywrite(char *input); // Input is the content to be written to shared memory.
void get_shm_cpy(int keyid); // Create and obtain the shared memory.
void delete_shm_cpy(); // Use shmctl to destroy the shared memory.
uint8_t shm_check_hold(volatile uint8_t *buf); // Check if the neural network is in training.
