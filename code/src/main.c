
#include "main.h"

static enum states prog_state = ST_INIT;
volatile static enum states processing_thread_state = ST_INIT;
static enum operations prog_operation = OP_INIT;

K_MSGQ_DEFINE(message_queue, sizeof(char *), QUEUE_LEN, QUEUE_TIMEOUT);
K_MSGQ_DEFINE(crypto_queue, sizeof(char *), QUEUE_LEN, QUEUE_TIMEOUT);

// Globally declare Devices
const struct device * uart_dev;
const struct device * crypto_dev;

static unsigned char * g_in_buffer = "Schoene Crypto Welt             ";
static unsigned char * g_out_buffer;
static unsigned char g_iv[AES_IV_LEN] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
static unsigned char g_key[AES_KEY_LEN] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
static uint32_t cap_flags;

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

        #if ALIVE_MESSAGES == TRUE
            printk("%sMain-Thread is alive%s \n", COLOR_RED, RESET_COLOR);
        #endif

        // send_string_to_processing_thread("E\n");

        cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_ENCRYPT);

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

        #if ALIVE_MESSAGES == TRUE
            sleep(1);
            printk("%sUART_in-Thread is alive%s \n", COLOR_GREEN, RESET_COLOR);
        #endif

        switch (prog_state) {

            case ST_INIT:

                // Wait for incoming Traffic
                if(!uart_poll_in(uart_dev,&uart_in)){

                    // printk("%sReceived : <%c> = <%i>%s",COLOR_GREEN,uart_in,uart_in,RESET_COLOR);

                    switch (uart_in) {
                        case 'd':
                        case 'D':
                            prog_state = ST_DECRYPT;
                            break;
                        case 'e':
                        case 'E':
                            prog_state = ST_ENCRYPT;
                            break;
                        case 'p':
                        case 'P':
                            send_string_to_processing_thread(PROCESSING_CHAR);
                            break;
                        case 'w':
                        case 'W':
                            send_string_to_processing_thread(WAIT_CHAR);
                            break;
                        case 'k':
                        case 'K':
                            // Ensure that Key is not changed during Encrytption/Decryption
                            if (processing_thread_state == ST_BUSY) {
                                prog_state = ST_KEY;
                            }
                            break;
                        case 'i':
                        case 'I':
                            // Ensure that IV is not changed during Encrytption/Decryption
                            if (processing_thread_state == ST_BUSY) {
                                prog_state = ST_IV;
                            }
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
                        buffer = malloc(len);
                    }
                }
                break;

            case ST_DATA:
                prog_state = ST_OP_SEL;
                iLauf = 0;
                while (len > iLauf){
                    if(!uart_poll_in(uart_dev,&uart_in)){
                        buffer[iLauf++] = uart_in;
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
                break;

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

            case ST_OP_DECRYPT:
                g_in_buffer = buffer;
                send_string_to_processing_thread(DECRYPT_CHAR);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_ENCRYPT:
                g_in_buffer = buffer;
                send_string_to_processing_thread(ENCRYPT_CHAR);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            default:
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                // free(buffer);
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

        #if ALIVE_MESSAGES == TRUE
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

void cbc_mode(const struct device *dev, uint8_t en_decrypt) {

    g_in_buffer = malloc(32);
    g_out_buffer = malloc(48);

    g_in_buffer = "Schoene Crypto Welt             ";

	struct cipher_ctx ini = {
		.keylen = AES_KEY_LEN,
		.key.bit_stream = g_key,
		.flags = cap_flags,
	};
	struct cipher_pkt buffers = {
		.in_buf = g_in_buffer,
		.in_len = 32,
		.out_buf_max = 48,
		.out_buf = g_out_buffer,
	};

	if (cipher_begin_session(crypto_dev, &ini, CRYPTO_CIPHER_ALGO_AES,
				 CRYPTO_CIPHER_MODE_CBC,
				 CRYPTO_CIPHER_OP_ENCRYPT)) {
		return;
	}

    print_data("Key : ", "%02X", g_key, AES_KEY_LEN);
    print_data("IV : ", "%02X", g_iv, AES_KEY_LEN);
    print_data("Input-Buffer : ", "%c", g_in_buffer, 32);
    print_data("Input-Buffer Hex : ", "%02X", g_in_buffer, 32);

	if (cipher_cbc_op(&ini, &buffers, g_iv)) {
		LOG_ERR("CBC mode ENCRYPT - Failed");
	}else{
        print_data("Encrypted : ", "%02X", g_out_buffer, 48);
        printf("Trying : \n");
        // print_data("Encrypted : ", "%c", g_out_buffer, 48);
        int iLauf = 16,iLauf2 = 0;
        while (iLauf2 <= 31) {
            if (g_out_buffer[iLauf] != 0xFF){
                printf("%02X", g_out_buffer[iLauf]);
                iLauf2++;
            }
            iLauf ++;
        }
        printf("\n");
    }

	cipher_free_session(dev, &ini);
}

void * process_thread(void * x) {

    char * message = "";

    while(1) {

        #if ALIVE_MESSAGES == TRUE
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
                case 'E':
                    processing_thread_state = ST_BUSY;
                    cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_ENCRYPT);
                    //TODO Ghoert aussi
                    // print_data("Encrypted : ","%X", g_out_buffer,strlen(g_out_buffer));
                    send_string_via_uart(g_out_buffer);
                    processing_thread_state = ST_INIT;
                    break;
                case 'D':
                    processing_thread_state = ST_BUSY;
                    cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_DECRYPT);
                    send_string_via_uart(g_out_buffer);
                    processing_thread_state = ST_INIT;
                    break;
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
