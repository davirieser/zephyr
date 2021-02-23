
// int usleep(useconds_t useconds);

// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/include/drivers/uart.h
//
/** Console I/O function */
// int (*poll_in)(const struct device *dev, unsigned char *p_char);
// void (*poll_out)(const struct device *dev, unsigned char out_char);
//
// /** Console I/O function */
// int (*err_check)(const struct device *dev);
//
// /** UART configuration functions */
// int (*configure)(const struct device *dev,
// 		 const struct uart_config *cfg);
// int (*config_get)(const struct device *dev, struct uart_config *cfg);

// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/include/posix/pthread.h
// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/tests/posix/common/src/pthread.c
// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/tests/posix/common/src/posix_rwlock.c
//
// int pthread_once(pthread_once_t *once, void (*initFunc)(void));
// void pthread_exit(void *retval);
// int pthread_join(pthread_t thread, void **status);
// int pthread_cancel(pthread_t pthread);
// int pthread_detach(pthread_t thread);
// int pthread_create(pthread_t *newthread, const pthread_attr_t *attr,
// 		   void *(*threadroutine)(void *), void *arg);
// int pthread_setcancelstate(int state, int *oldstate);
// int pthread_attr_setschedparam(pthread_attr_t *attr,
// 			       const struct sched_param *schedparam);
// int pthread_setschedparam(pthread_t pthread, int policy,
// 			  const struct sched_param *param);
// int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
// int pthread_rwlock_init(pthread_rwlock_t *rwlock,
// 			const pthread_rwlockattr_t *attr);
// int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
// int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock,
// 			       const struct timespec *abstime);
// int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock,
// 			       const struct timespec *abstime);
// int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
// int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
// int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
// int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
// int pthread_key_create(pthread_key_t *key,
// 		void (*destructor)(void *));

#include <zephyr.h>
#include <device.h>
#include <sys/printk.h>
#include <drivers/uart.h>
#include <crypto/cipher.h>
#include <crypto/cipher_structs.h>
#include <logging/log.h>
#include <pthread.h>
#include <mqueue.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
#define UART_DRV_NAME "UART_0"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
LOG_MODULE_REGISTER(main);

// Create Mutex for locking the Message-Queue
// PTHREAD_MUTEX_DEFINE(queue_lock);

// 3 Threads + Main-Thread
#define NUM_THREADS 3

int validate_hw_compatibility(const struct device *dev);
void cbc_mode(const struct device *dev);
void state_machine();
void print_data(
    const char *title,
    const char *formatter,
    const void* data,
    int len
);

// Declare Enum for State Machine
enum states{INIT,IDLE,BUSY,AVAIL,ENCRYPT,DECRYPT,DLEN,DATA,KEY,IV,OP,OP_KEY,OP_IV,OP_DECRYPT};
enum operations{OP_INIT,SET_KEY,SET_IV,OP_ENCRYPT,OP_DECRYPT};

static enum states prog_state = INIT;
static enum operations prog_operation = OP_INIT;

// Globally declare Devices
const struct device * uart_dev;
const struct device * crypto_dev;

#define AES_KEY_LEN 16
#define AES_IV_LEN 16

uint8_t in_message_queue_pointer = 0;
char in_message_queue[255];
uint8_t out_message_queue_pointer = 0;
char out_message_queue[255];

void main(void) {

	// uint8_t rx_buf[10] = {0};
    // uint8_t tx_buf[10] = {0x48,0x61,0x6C,0x6C,0x6F,0x21,0x20,0x20,0x20,0x0A};

	uart_dev = device_get_binding(UART_DRV_NAME);
	if (!uart_dev) {
        LOG_ERR("%s pseudo device not found", UART_DRV_NAME);
        return;
    }
	crypto_dev = device_get_binding(CRYPTO_DRV_NAME);
	if (!crypto_dev) {
        LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
        return;
    }

	if (validate_hw_compatibility(crypto_dev)) {
            LOG_ERR("Incompatible h/w");
            return;
    }

    // Log Crypto-Action
	// cbc_mode(crypto_dev);

    state_machine();

}

/* -------------------------------------------------------------------------- */
/* ----- UART SECTION ------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

// KConfig
// https://github.com/zephyrproject-rtos/zephyr/blob/master/drivers/serial/Kconfig.native_posix
//
// Code
// https://github.com/zephyrproject-rtos/zephyr/blob/master/include/drivers/uart.h
// https://github.com/zephyrproject-rtos/zephyr/blob/master/drivers/serial/uart_native_posix.c

void state_machine() {

    unsigned char uart_in = '\0';
    uint8_t iLauf = 0, len = 0;
    unsigned char * buffer;

    while (1) {

        if(!uart_poll_in(uart_dev,&uart_in)){

            LOG_INF("Received <%c> = <%d>",uart_in,uart_in);

            switch (prog_state) {

                case INIT:

                    switch (uart_in) {
                        case 'P':
                            prog_state = AVAIL;
                            break;
                        case 'D':
                            prog_state = DECRYPT;
                            break;
                        case 'K':
                            prog_state = KEY;
                            break;
                        case 'I':
                            prog_state = IV;
                            break;
                        case 'W':
                            // sleep(10);
                            prog_state = BUSY;
                            break;
                        case '.':
                            uart_poll_out(uart_dev,'.');
                        default:
                            prog_state = INIT;
                            break;
                    };

                case DECRYPT:
                    prog_state = DLEN;
                    prog_operation = OP_DECRYPT;
                    break;

                case ENCRYPT:
                    prog_state = DLEN;
                    prog_operation = OP_ENCRYPT;
                    break;

                case DLEN:
                    prog_state = DATA;
                    while (1) {
                        if(!uart_poll_in(uart_dev,&uart_in)){
                            len = uart_in;
                            break;
                        }
                        buffer = malloc(len);
                    }
                    break;

                case KEY:
                    prog_state = DATA;
                    prog_operation = SET_KEY;
                    buffer = malloc(AES_KEY_LEN);
                    len = AES_KEY_LEN;
                    break;

                case IV:
                    prog_state = DATA;
                    prog_operation = SET_IV;
                    buffer = malloc(AES_IV_LEN);
                    len = AES_IV_LEN;
                    break;

                case DATA:
                    prog_state = OP;
                    iLauf = 0;
                    while (len > iLauf){
                        if(!uart_poll_in(uart_dev,&uart_in)){
                            buffer[iLauf++] = uart_in;
                            break;
                        }
                    }
                    break;

                case OP:
                    switch (prog_operation){
                        case SET_KEY:
                            prog_state = OP_KEY;
                            break;
                        case SET_IV:
                            prog_state = OP_IV;
                            break;
                        case OP_DECRYPT:
                            prog_state = OP_DECRYPT;
                            break;
                        case OP_ENCRYPT:
                            prog_state = OP_ENCRYPT;
                            break;
                        default:
                            prog_state = INIT;
                            break;
                    };

                // TODO
                // case OP_IV:
                //     iv = buffer;
                //     break;
                //
                // case OP_KEY:
                //     key = buffer;
                //     break;
                //
                // case OP_DECRYPT:
                //     cbc_mode();
                //     break;
                //
                // case OP_ENCRYPT:
                //     cbc_mode();
                //     break;

                default:
                    prog_state = INIT;
                    prog_operation = OP_INIT;
                    break;

            }

        }

    }

}

/* -------------------------------------------------------------------------- */
/* ----- CRYPTO SECTION ----------------------------------------------------- */
/* -------------------------------------------------------------------------- */

// https://docs.zephyrproject.org/2.4.0/reference/crypto/index.html#c.cipher_ctx
// https://github.com/zephyrproject-rtos/zephyr/tree/master/drivers/crypto
// https://github.com/zephyrproject-rtos/zephyr/tree/master/samples/drivers/crypto

uint32_t cap_flags;

static uint8_t key[16] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};

static uint8_t plaintext[64] = {
    0x53, 0x63, 0x68, 0x6F, 0x65, 0x6E, 0x65, 0x20,
    0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x20, 0x57,
    0x65, 0x6C, 0x74, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D
};

int validate_hw_compatibility(const struct device *dev)
{
    uint32_t flags = 0U;

    flags = cipher_query_hwcaps(dev);
    if ((flags & CAP_RAW_KEY) == 0U) {
            LOG_INF("Please provision the key separately "
                    "as the module doesnt support a raw key");
            return -1;
    }

    if ((flags & CAP_SYNC_OPS) == 0U) {
            LOG_ERR("The app assumes sync semantics. "
              "Please rewrite the app accordingly before proceeding");
            return -1;
    }

    if ((flags & CAP_SEPARATE_IO_BUFS) == 0U) {
            LOG_ERR("The app assumes distinct IO buffers. "
            "Please rewrite the app accordingly before proceeding");
            return -1;
    }

    // LOG_INF("CRYPTO_CAPABILITIES : %d\n", flags);

    cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;

    return 0;

}

// See https://github.com/zephyrproject-rtos/zephyr/tree/master/include/crypto

void cbc_mode(const struct device *dev)
{
    uint8_t encrypted[80] = {0};
    uint8_t decrypted[64] = {0};
	uint32_t cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;
    struct cipher_ctx ini = {
            .keylen = sizeof(key),
            .key.bit_stream = key,
            .flags = cap_flags,
    };
    struct cipher_pkt encrypt = {
            .in_buf = plaintext,
            .in_len = sizeof(plaintext),
            .out_buf_max = sizeof(encrypted),
            .out_buf = encrypted,
    };
    struct cipher_pkt decrypt = {
            .in_buf = encrypt.out_buf,
            .in_len = sizeof(encrypted),
            .out_buf = decrypted,
            .out_buf_max = sizeof(decrypted),
    };

    static uint8_t iv[16] = {
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
    };

    if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
                             CRYPTO_CIPHER_MODE_CBC,
                             CRYPTO_CIPHER_OP_ENCRYPT)) {
            return;
    }

    if (cipher_cbc_op(&ini, &encrypt, iv)) {
            LOG_ERR("CBC mode ENCRYPT - Failed");
            goto out;
    }

	print_data("\n\nEncrypted : ","%02X",encrypt.out_buf,encrypt.out_buf_max);

    // LOG_INF("Output (encryption): %s", encrypt.out_buf);

    // if (memcmp(encrypt.out_buf, cbc_ciphertext, sizeof(cbc_ciphertext))) {
    //         LOG_ERR("CBC mode ENCRYPT - Mismatch between expected and "
    //                     "returned cipher text");
    //         // print_buffer_comparison(cbc_ciphertext, encrypt.out_buf,
    //                                 // sizeof(cbc_ciphertext));
    //         goto out;
    // }

    // LOG_INF("CBC mode ENCRYPT - Match");
    cipher_free_session(dev, &ini);

    if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
                             CRYPTO_CIPHER_MODE_CBC,
                             CRYPTO_CIPHER_OP_DECRYPT)) {
            return;
    }

    /* TinyCrypt keeps IV at the start of encrypted buffer */
    if (cipher_cbc_op(&ini, &decrypt, encrypted)) {
            LOG_ERR("CBC mode DECRYPT - Failed");
            goto out;
    }

    // LOG_INF("Output (decryption): %s", decrypt.out_buf);

    if (memcmp(decrypt.out_buf, plaintext, sizeof(plaintext))) {
            LOG_ERR("CBC mode DECRYPT - Mismatch between plaintext and "
                        "decrypted cipher text");
            // print_buffer_comparison(plaintext, decrypt.out_buf,
                                    // sizeof(plaintext));
            goto out;
    }

	print_data("\n\nDecryted : ","%02X",decrypt.out_buf,decrypt.out_buf_max);

    // LOG_INF("CBC mode DECRYPT - Match");
out:
    cipher_free_session(dev, &ini);

}

/* ---- Print Encrypted and Decrypted data packets -------------------------- */

void print_data(
    const char *title,
    const char *formatter,
    const void* data,
    int len
){

    // Set Terminal Color
	printk("%s\"",title);

	const unsigned char * p = (const unsigned char*)data;
	int i = 0;

	for (; i<len; ++i)
		printk(formatter, *p++);

    // Reset Terminal Color
	printk("\"\n");

}
