
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
// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/samples/synchronization/src/main.c
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
//
// https://github.com/zephyrproject-rtos/zephyr/blob/backport-29181-to-v2.4-branch/include/posix/mqueue.h
// https://github.com/zephyrproject-rtos/zephyr/blob/master/lib/posix/mqueue.c
//
// mqd_t mq_open(const char *name, int oflags, ...);
// int mq_close(mqd_t mqdes);
// int mq_unlink(const char *name);
// int mq_getattr(mqd_t mqdes, struct mq_attr *mqstat);
// int mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
// 		   unsigned int *msg_prio);
// int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
// 	    unsigned int msg_prio);
// int mq_setattr(mqd_t mqdes, const struct mq_attr *mqstat,
// 	       struct mq_attr *omqstat);
// int mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
// 			unsigned int *msg_prio, const struct timespec *abstime);
// int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
// 		 unsigned int msg_prio, const struct timespec *abstime);

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <zephyr.h>
#include <device.h>
#include <sys/printk.h>
#include <drivers/uart.h>
#include <crypto/cipher.h>
#include <crypto/cipher_structs.h>
#include <logging/log.h>
#include <pthread.h>
#include <posix/mqueue.h>
#include <posix/posix_types.h>

#define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
#define UART_DRV_NAME "UART_0"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
LOG_MODULE_REGISTER(main);

#define ALIVE_MESSAGES 0

// 3 Threads + Main-Thread
#define NUM_THREADS 3
#define QUEUE_LEN 20
#define QUEUE_TIMEOUT 1

#define AES_KEY_LEN 16
#define AES_IV_LEN 16

#define RESET_COLOR "\033[0m"
#define COLOR_LIGHT_GRAY "\033[0;2m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE "\033[0;34m"

#define MAIN_MESSAGE "Hello from Main-Thread"
#define PROCESSING_MESSAGE "PROCESSING AVAILABLE\n"
#define BUSY_MESSAGE "BUSY\n"
#define POINT_STRING ".\n"

#define ENCRYPT_CHAR "E\n"
#define DECRYPT_CHAR "D\n"
#define PROCESSING_CHAR "P\n"
#define WAIT_CHAR "W\n"

#define PROCESSING_THREAD_IDLE 0
#define PROCESSING_THREAD_BUSY 1

void init_threads(pthread_t * threads);

/* ----- UART SECTION ------------------------------------------------------- */
void state_machine();
void send_via_uart(unsigned char tx);
int send_string_via_uart(unsigned char * tx);
int send_string_to_processing_thread(unsigned char * tx);
void * uart_in_thread(void * x);
void * uart_out_thread(void * x);
/* ----- CRYPTO SECTION ----------------------------------------------------- */
int validate_hw_compatibility(const struct device *dev);
void cbc_mode(const struct device *dev,uint8_t en_decrypt);
void * process_thread(void * x);
void print_data(
    const char *title,
    const char *formatter,
    const void* data,
    int len
);

// Declare Enums for State Machine
enum states{
    ST_INIT,ST_BUSY,ST_AVAIL,ST_ENCRYPT,ST_DECRYPT,ST_DLEN,ST_DATA,ST_KEY,ST_IV,
    ST_OP_SEL,ST_OP_KEY,ST_OP_IV,ST_OP_DECRYPT,ST_OP_ENCRYPT
};
enum operations{OP_INIT,OP_KEY,OP_IV,OP_ENCRYPT,OP_DECRYPT};

// Can only be written by UART_READ-Thread
// Can be read by all Threads
static enum states prog_state = ST_INIT;
volatile static enum states processing_thread_state = ST_INIT;
static enum operations prog_operation = OP_INIT;

K_MSGQ_DEFINE(message_queue, sizeof(char *), QUEUE_LEN, QUEUE_TIMEOUT);
K_MSGQ_DEFINE(crypto_queue, sizeof(char *), QUEUE_LEN, QUEUE_TIMEOUT);

// Globally declare Devices
const struct device * uart_dev;
const struct device * crypto_dev;

unsigned char * g_in_buffer;
unsigned char * g_out_buffer;
unsigned char g_iv[AES_IV_LEN] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
unsigned char g_key[AES_KEY_LEN] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
uint32_t cap_flags;

void main(void) {

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

    pthread_t threads[NUM_THREADS];

    init_threads(threads);

    while(1) {


        #if ALIVE_MESSAGES == 0
            printk("%sMain-Thread is alive%s \n", COLOR_RED, RESET_COLOR);
        #endif

        // printk("%sMain-Thread-Address = %i%s\n", COLOR_BLUE, PROCESSING_CHAR, RESET_COLOR);
        // send_string_to_processing_thread(PROCESSING_CHAR);

        sleep(5);

    }

}

void init_threads(pthread_t * threads) {

    int ret, i;
	pthread_attr_t attr[NUM_THREADS] = {};
    void *(*thread_routines[])(void *) = {uart_in_thread,uart_out_thread,process_thread};

	for (i = 0; i < NUM_THREADS; i++) {

		ret = pthread_create(&threads[i], &attr[i], thread_routines[i], INT_TO_POINTER(i));
        if (ret != 0) {
            LOG_ERR("Error creating Thread");
        }

    }

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
    unsigned char * buffer = "";

    while (1) {

        #if ALIVE_MESSAGES == 0
            sleep(1);
            printk("%sUART_in-Thread is alive%s \n", COLOR_GREEN, RESET_COLOR);
        #endif

        switch (prog_state) {

            case ST_INIT:

                // Wait for incoming Traffic
                if(!uart_poll_in(uart_dev,&uart_in)){

                    // printk("%sReceived : <%c> = <%i>%s",COLOR_GREEN,uart_in,uart_in,RESET_COLOR);

                    switch (uart_in) {
                        case 'D':
                            prog_state = ST_DECRYPT;
                            break;
                        case 'E':
                            prog_state = ST_ENCRYPT;
                            break;
                        case 'P':
                            send_string_to_processing_thread(PROCESSING_CHAR);
                            break;
                        case 'W':
                            send_string_to_processing_thread(WAIT_CHAR);
                            break;
                        case 'K':
                            prog_state = ST_KEY;
                            break;
                        case 'I':
                            prog_state = ST_IV;
                            break;
                        // Echo-Test
                        case '.':
                            send_string_via_uart(POINT_STRING);
                            if (processing_thread_state == ST_BUSY) {
                                send_string_via_uart(BUSY_MESSAGE);
                            }
                            break;
                        default:
                            break;
                    };

                }
                break;

            case ST_DECRYPT:
                prog_state = ST_DLEN;
                prog_operation = OP_DECRYPT;
                break;

            case ST_ENCRYPT:
                prog_state = ST_DLEN;
                prog_operation = OP_ENCRYPT;
                break;

            case ST_KEY:
                prog_state = ST_DATA;
                prog_operation = OP_KEY;
                buffer = malloc(AES_KEY_LEN);
                len = AES_KEY_LEN;
                break;

            case ST_IV:
                prog_state = ST_DATA;
                prog_operation = OP_IV;
                buffer = malloc(AES_IV_LEN);
                len = AES_IV_LEN;
                break;

            case ST_DLEN:
                prog_state = ST_DATA;
                while (1) {
                    if(!uart_poll_in(uart_dev,&uart_in)){
                        len = uart_in;
                        break;
                    }
                    buffer = malloc(len);
                    g_out_buffer = malloc(len);
                }
                break;

            case ST_DATA:
                prog_state = ST_OP_SEL;
                iLauf = 0;
                while (len > iLauf){
                    if(!uart_poll_in(uart_dev,&uart_in)){
                        buffer[iLauf++] = uart_in;
                        break;
                    }
                }
                break;

            case ST_OP_SEL:
                switch (prog_operation){
                    case OP_KEY:
                        prog_state = ST_OP_KEY;
                        break;
                    case OP_IV:
                        prog_state = ST_OP_IV;
                        break;
                    case OP_DECRYPT:
                        prog_state = ST_OP_DECRYPT;
                        break;
                    case OP_ENCRYPT:
                        prog_state = ST_OP_ENCRYPT;
                        break;
                    default:
                        prog_state = ST_INIT;
                        free(buffer);
                        free(g_out_buffer);
                        break;
                };

            case ST_OP_IV:
                strcpy(buffer,g_iv);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_KEY:
                strcpy(buffer,g_key);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            // case ST_OP_DECRYPT:
            //     g_in_buffer = buffer;
            //     send_string_to_processing_thread(DECRYPT_CHAR);
            //     while(processing_thread_state != ST_INIT);
            //     prog_state = ST_INIT;
            //     prog_operation = OP_INIT;
            //     break;
            //
            // case ST_OP_ENCRYPT:
            //     g_in_buffer = buffer;
            //     send_string_to_processing_thread(ENCRYPT_CHAR);
            //     while(processing_thread_state != ST_INIT);
            //     prog_state = ST_INIT;
            //     prog_operation = OP_INIT;
            //     break;

            default:
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                free(buffer);
                break;

        }

    }

}

int send_string_via_uart(unsigned char * tx) {

    k_msgq_put(&message_queue,&tx,K_FOREVER);

    return 0;

}

int send_string_to_processing_thread(unsigned char * tx) {

    k_msgq_put(&crypto_queue,&tx,K_FOREVER);

    return 0;

}

void * uart_in_thread(void * x) {

    state_machine();

    return x;

}

void * uart_out_thread(void * x) {

    int iLauf = 0;
    char * message = "";

    while (1) {

        #if ALIVE_MESSAGES == 0
            sleep(1);
            printk("%sUART_out-Thread is alive%s \n",COLOR_YELLOW,RESET_COLOR);
        #endif

        // Block until Data is available
        if(!k_msgq_get(&message_queue,&message,K_NO_WAIT)) {

            // Log received data
            // printk("%sMessage Queue : <%s>%s\n",COLOR_GREEN, message,RESET_COLOR);

            // Send received data via UART
            while(message[iLauf] != 0) {
                // printk("%sWriting <%c> = <%i>%s\n", COLOR_RED, message[iLauf], message[iLauf], RESET_COLOR);
                uart_poll_out(uart_dev,message[iLauf++]);
            }
            // Reset Counter
            iLauf = 0;

        }

    }

    return x;

}

/* -------------------------------------------------------------------------- */
/* ----- CRYPTO SECTION ----------------------------------------------------- */
/* -------------------------------------------------------------------------- */

// https://docs.zephyrproject.org/2.4.0/reference/crypto/index.html#c.cipher_ctx
// https://github.com/zephyrproject-rtos/zephyr/tree/master/drivers/crypto
// https://github.com/zephyrproject-rtos/zephyr/tree/master/samples/drivers/crypto

int validate_hw_compatibility(const struct device *dev) {

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

    cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;

    return 0;

}

// See https://github.com/zephyrproject-rtos/zephyr/tree/master/include/crypto

void cbc_mode(const struct device *dev,uint8_t en_decrypt){

    struct cipher_ctx ini = {
        .keylen = sizeof(g_key),
        .key.bit_stream = g_key,
        .flags = cap_flags,
    };
    struct cipher_pkt buffers = {
        .in_buf = g_in_buffer,
        .in_len = sizeof(g_in_buffer),
        .out_buf_max = sizeof(g_out_buffer),
        .out_buf = g_out_buffer,
    };

    if (
        cipher_begin_session(
            dev, &ini, CRYPTO_CIPHER_ALGO_AES,
            CRYPTO_CIPHER_MODE_CBC,
            en_decrypt
        )
    ) {
            return;
    }

    if (cipher_cbc_op(&ini, &buffers, g_iv)) {
        LOG_ERR("CBC mode ENCRYPT - Failed");
    }

    cipher_free_session(dev, &ini);

}

void * process_thread(void * x) {

    char * message = "";

    while(1) {

        #if ALIVE_MESSAGES == 0
            sleep(1);
            printk("%sProcessing-Thread is alive%s \n", COLOR_BLUE, RESET_COLOR);
        #endif

        // Block until Data is available
        if(!k_msgq_get(&crypto_queue,&message,K_NO_WAIT)) {

            printk("%sProcessing Thread received : <%c> %s \n", COLOR_RED,message[0],RESET_COLOR);

            switch (message[0]) {
                case 'W':
                    processing_thread_state = ST_BUSY;
                    sleep(5);
                    processing_thread_state = ST_INIT;
                    break;
                case 'P':
                    processing_thread_state = ST_BUSY;
                    send_string_via_uart(PROCESSING_MESSAGE);
                    processing_thread_state = ST_INIT;
                    break;
            //     case 'E':
            //         processing_thread_state = ST_BUSY;
            //         cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_ENCRYPT);
            //         send_string_via_uart(g_out_buffer);
            //         processing_thread_state = ST_INIT;
            //         break;
            //     case 'D':
            //         processing_thread_state = ST_BUSY;
            //         cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_DECRYPT);
            //         send_string_via_uart(g_out_buffer);
            //         processing_thread_state = ST_INIT;
            //         break;
                default:
                    processing_thread_state = ST_INIT;
                    break;
            }
        }

    }

    return x;

}

/* ---- Print Encrypted and Decrypted data packets -------------------------- */

void print_data(
    const char *title,
    const char *formatter,
    const void* data,
    int len
){

	printk("%s\"",title);

	const char * p = (const char*)data;
	int i = 0;

	for (; i<len; ++i)
		printk(formatter, *p++);

	printk("\"\n");

}
