// Add to the same directory as afl-fuzz.c.
#include "shmutils.h"

// If the first byte of shm is 0, it means the shm is handed over to the fuzzer.
// If the first byte of shm is 1, it means the shm is handed over to Python.

char *CPY_SHM = NULL;
int cpy_shmid = -1;

uint8_t *shm_check(volatile uint8_t *buf)
{
    while (1)
    {
        if (buf[0] == 0) // Check if the fuzzer can write.
        {
            break;
        }
        else if (buf[0] == 2)
            return NULL;
    }
    return (uint8_t *)(buf + 2); // Return a pointer to the memory to write (offset + 2); offset 0 is the flag byte, offset 1 is the string length.
}

uint8_t shm_check_hold(volatile uint8_t *buf){
    return (buf[0] == 2);
}

void shm_spin_unlock()
{
    CPY_SHM[0] = 1; // Set the first byte to 1, handing over the shm to Python.
}

int mywrite(char *input) // Input is the content to be written to shared memory.
{
    char *target;
    target = shm_check(CPY_SHM); // Check if writing is allowed, and if so, get the target memory to write.
    if (target == NULL) return 0;
    int len = strlen(input);
    CPY_SHM[1] = (uint8_t)len; // Set the string length at offset +1.
    strcpy(target, input);
    // printf("write success\n");
    shm_spin_unlock();
    return 1;
    // printf("share mem unlock\n");
}

void get_shm_cpy(int keyid)
{
    key_t key = keyid;
    if (key < 0)
        perror("ftok error");

    cpy_shmid = shmget(key, SHMSIZE, IPC_CREAT | IPC_EXCL | 0664); // Create shared memory.
    if (cpy_shmid == -1)
    {
        if (errno == EEXIST)
        {
            printf("shared memory already exists\n");
            cpy_shmid = shmget(key, 0, 0);
            printf("reference cpy_shmid = %d\n", cpy_shmid);
        }
        else
        {
            perror("errno");
        }
    }

    /* Do not specify the address to attach
     * and attach for read & write */
    if ((CPY_SHM = shmat(cpy_shmid, 0, 0)) == (void *)-1)
    {
        if (shmctl(cpy_shmid, IPC_RMID, NULL) == -1)
            perror("shmctl error");
        else
        {
            printf("Attach shared memory failed\n");
            printf("remove shared memory identifier successful\n");
        }

        perror("shmat error");
    }
    CPY_SHM[0] = 0; // Set the first byte of shared memory to 0, indicating shared memory is acquired and ready for writing.

}

void delete_shm_cpy()
{
    if (shmdt(CPY_SHM) < 0) // First detach shared memory.
        perror("shmdt error");

    if (shmctl(cpy_shmid, IPC_RMID, NULL) == -1) // Then delete shared memory.
        perror("shmctl error");
    else
    {
        printf("Finally\n");
        printf("remove shared memory identifier successful\n");
    }
}
