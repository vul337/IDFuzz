// Add to the same directory as afl-fuzz.c.
#include "shmutils.h"

#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <sched.h>
#include <unistd.h>

// If the first byte of shm is 0, it means the shm is handed over to the fuzzer.
// If the first byte of shm is 1, it means the shm is handed over to Python.
// If the first byte of shm is 2, Python is training and the fuzzer must not wait for it.
//
// Only the current owner writes to the shm, so a reply that arrives after the
// fuzzer stopped waiting is harmless: the fuzzer simply overwrites it with the
// next request. Requests never block, and replies are waited for with a
// timeout, so a dead or missing Python process degrades IDFuzz to plain
// fuzzing instead of hanging it.

char *CPY_SHM = NULL;
int cpy_shmid = -1;
static pid_t cpy_owner_pid = -1; // Forked children inherit atexit handlers; only the creator may delete.

static uint8_t load_flag(volatile uint8_t *buf)
{
    return __atomic_load_n(buf, __ATOMIC_ACQUIRE);
}

static void store_flag(uint8_t val)
{
    __atomic_store_n((uint8_t *)CPY_SHM, val, __ATOMIC_RELEASE);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint64_t reply_timeout_ms(void)
{
    static uint64_t timeout = 0;
    if (!timeout)
    {
        char *env = getenv("IDFUZZ_NN_TIMEOUT_MS");
        timeout = SHM_REPLY_TIMEOUT_MS;
        if (env && atoi(env) > 0)
            timeout = (uint64_t)atoi(env);
    }
    return timeout;
}

uint8_t *shm_check(volatile uint8_t *buf)
{
    uint64_t deadline = now_ms() + reply_timeout_ms();
    uint32_t spins = 0;
    struct timespec nap = {0, 100 * 1000}; // 100us

    while (1)
    {
        uint8_t flag = load_flag(buf);
        if (flag == 0) // Check if the fuzzer can write.
        {
            break;
        }
        else if (flag == 2)
            return NULL;

        // Spin briefly for low latency, then back off so we don't burn a core.
        if (++spins < 1000)
        {
            sched_yield();
            continue;
        }
        if (now_ms() > deadline)
            return NULL;
        nanosleep(&nap, NULL);
    }
    return (uint8_t *)(buf + 2); // Return a pointer to the memory to write (offset + 2); offset 0 is the flag byte, offset 1 is the string length.
}

uint8_t shm_check_hold(volatile uint8_t *buf){
    return (load_flag(buf) == 2);
}

void shm_spin_unlock()
{
    store_flag(1); // Set the first byte to 1, handing over the shm to Python.
}

int mywrite(char *input) // Input is the content to be written to shared memory.
{
    if (!CPY_SHM) return 0;
    // Never wait here: if Python has not handed the shm back yet (busy, not
    // started, or dead), skip this request.
    if (load_flag((volatile uint8_t *)CPY_SHM) != 0) return 0;
    size_t len = strlen(input);
    if (len > SHM_MSG_MAX) return 0;
    CPY_SHM[1] = (uint8_t)len; // Set the string length at offset +1.
    memcpy(CPY_SHM + 2, input, len);
    CPY_SHM[2 + len] = '\0';
    shm_spin_unlock();
    return 1;
}

int myread(char *out, size_t cap)
{
    if (!CPY_SHM || !cap) return 0;
    uint8_t *reply = shm_check((volatile uint8_t *)CPY_SHM);
    if (!reply) return 0;
    size_t len = (uint8_t)CPY_SHM[1];
    if (len > SHM_MSG_MAX) len = SHM_MSG_MAX;
    if (len >= cap) len = cap - 1;
    memcpy(out, reply, len);
    out[len] = '\0';
    return 1;
}

void get_shm_cpy(int keyid)
{
    key_t key = keyid;
    if (key <= 0)
    {
        fprintf(stderr, "[-] Invalid C-Python shared memory key %d\n", keyid);
        exit(1);
    }

    cpy_shmid = shmget(key, SHMSIZE, IPC_CREAT | IPC_EXCL | 0664); // Create shared memory.
    if (cpy_shmid == -1 && errno == EEXIST)
    {
        // A segment with this key already exists. If the process that created
        // it is still alive, another campaign is using this key; sharing it
        // would mix up both campaigns' messages. Otherwise it is left over
        // from a run that did not clean up, so replace it.
        struct shmid_ds ds;
        int old_id = shmget(key, 0, 0);
        if (old_id == -1 || shmctl(old_id, IPC_STAT, &ds) == -1)
        {
            perror("[-] Unable to inspect existing shared memory");
            exit(1);
        }
        if (ds.shm_cpid > 0 && (kill(ds.shm_cpid, 0) == 0 || errno == EPERM))
        {
            fprintf(stderr, "[-] Shared memory key %d is in use by another process (pid %d). "
                            "Pick a different -K value.\n", keyid, (int)ds.shm_cpid);
            exit(1);
        }
        printf("removing stale shared memory for key %d (creator pid %d is gone)\n",
               keyid, (int)ds.shm_cpid);
        if (shmctl(old_id, IPC_RMID, NULL) == -1)
        {
            perror("[-] Unable to remove stale shared memory");
            exit(1);
        }
        cpy_shmid = shmget(key, SHMSIZE, IPC_CREAT | IPC_EXCL | 0664);
    }
    if (cpy_shmid == -1)
    {
        perror("[-] Unable to create C-Python shared memory");
        exit(1);
    }

    /* Do not specify the address to attach
     * and attach for read & write */
    if ((CPY_SHM = shmat(cpy_shmid, 0, 0)) == (void *)-1)
    {
        CPY_SHM = NULL;
        perror("[-] shmat error");
        shmctl(cpy_shmid, IPC_RMID, NULL);
        exit(1);
    }
    memset(CPY_SHM, 0, SHMSIZE);
    store_flag(0); // Set the first byte of shared memory to 0, indicating shared memory is acquired and ready for writing.

    // Make sure the segment does not outlive the fuzzer on FATAL() exits.
    cpy_owner_pid = getpid();
    atexit(delete_shm_cpy);
}

void delete_shm_cpy()
{
    if (!CPY_SHM || getpid() != cpy_owner_pid) return; // Already deleted, or a forked child.

    if (shmdt(CPY_SHM) < 0) // First detach shared memory.
        perror("shmdt error");
    CPY_SHM = NULL;

    if (shmctl(cpy_shmid, IPC_RMID, NULL) == -1) // Then delete shared memory.
        perror("shmctl error");
    else
    {
        printf("Finally\n");
        printf("remove shared memory identifier successful\n");
    }
    cpy_shmid = -1;
}
