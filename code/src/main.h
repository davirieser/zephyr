
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

#define FALSE 0x0
#define TRUE 0x1

#define ALIVE_MESSAGES FALSE

#define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
#define UART_DRV_NAME "UART_0"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
LOG_MODULE_REGISTER(main);

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