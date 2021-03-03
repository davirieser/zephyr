
#include "main.h"

static enum states prog_state = ST_INIT;
volatile static enum states processing_thread_state = ST_INIT;
static enum operations prog_operation = OP_INIT;

K_MSGQ_DEFINE(message_queue, sizeof(struct uart_message *), QUEUE_LEN, QUEUE_TIMEOUT);
K_MSGQ_DEFINE(crypto_queue, sizeof(char *), QUEUE_LEN, QUEUE_TIMEOUT);

// Globally declare Devices
const struct device * uart_dev;
const struct device * crypto_dev;

// Create UART_Config
const struct uart_config uart_cfg = {
		.baudrate = 115200,
		.parity = UART_CFG_PARITY_NONE,
		.stop_bits = UART_CFG_STOP_BITS_1,
		.data_bits = UART_CFG_DATA_BITS_8,
		.flow_ctrl = UART_CFG_FLOW_CTRL_NONE
	};

// Create global Input-and-Output-Buffer-Pointers
static uint8_t * g_in_buffer = "Schoene Crypto Welt             ";
static uint8_t * g_out_buffer;
// Create global Buffer-Length-Variable
static uint16_t buffer_length = 32;
// Create contingous IV and Key
static uint8_t g_iv_key[AES_IV_LEN + AES_KEY_LEN] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
// Create Pointer to Key
uint8_t * g_key = g_iv_key + AES_IV_LEN;
// Create global Struct for Crypto-Hardware-Capability-Flags
static uint32_t cap_flags;

void main(void) {

	uart_dev = device_get_binding(UART_DRV_NAME);
	if (!uart_dev) {
        LOG_ERR("%s pseudo device not found", UART_DRV_NAME);
        return;
    }
    if(!uart_configure(uart_dev, &uart_cfg)) {
        LOG_ERR("Error during UART-Config");
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

        #if PROCESS_ALIVE == TRUE
	        printk("%sMain-Thread is alive%s \n", COLOR_RED, RESET_COLOR);
        #endif

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

    uint8_t uart_in = '\0';
    uint8_t iLauf = 0, len = 0;
    uint8_t * buffer = "";

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
                            send_string_to_processing_thread(PROCESSING_STRING);
                            break;
                        case 'w':
                        case 'W':
                            send_string_to_processing_thread(WAIT_STRING);
                            break;
                        case 'k':
                        case 'K':
                            // Ensure that Key is not changed during Encrytption/Decryption
                            if (!(processing_thread_state == ST_BUSY)) {
                                prog_state = ST_KEY;
                            }
                            break;
                        case 'i':
                        case 'I':
                            // Ensure that IV is not changed during Encrytption/Decryption
                            if (!(processing_thread_state == ST_BUSY)) {
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
                buffer = (uint8_t *) malloc(AES_KEY_LEN);
                len = AES_KEY_LEN;
                break;

            case ST_IV:
                prog_state = ST_DATA;
                prog_operation = OP_IV;
                buffer = (uint8_t *) malloc(AES_IV_LEN);
                len = AES_IV_LEN;
                break;

            case ST_DLEN:
                prog_state = ST_DATA;
                while (1) {
                    if(!uart_poll_in(uart_dev,&uart_in)){
                        buffer_length = uart_in;
						len = buffer_length;
						if (prog_operation == OP_DECRYPT) {
	                        buffer = (uint8_t *) malloc((buffer_length + AES_IV_LEN) * sizeof(uint8_t));
							memcpy(buffer, g_iv_key, AES_IV_LEN);
							buffer += AES_IV_LEN;
						}else{
	                        buffer = (uint8_t *) malloc(buffer_length * sizeof(uint8_t));
						}
						if(!buffer){
							prog_state = ST_INIT;
							prog_operation = OP_INIT;
							LOG_ERR("Error allocating Memory for Input Buffer");
						}
						break;
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
				// print_data("Received : ", "%02X", buffer, buffer_length);
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
						// print_data("Decrypting : ", "%02X", g_in_buffer, buffer_length);
						buffer -= AES_IV_LEN;
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
                memcpy(g_iv_key,buffer,AES_IV_LEN);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_KEY:
                memcpy(g_key,buffer,AES_KEY_LEN);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_DECRYPT:
                g_in_buffer = buffer;
                send_string_to_processing_thread(DECRYPT_STRING);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_ENCRYPT:
                g_in_buffer = buffer;
                send_string_to_processing_thread(ENCRYPT_STRING);
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

int send_string_via_uart(struct uart_message tx) {

    k_msgq_put(&message_queue,&tx,K_FOREVER);

    return 0;

}

int send_string_to_processing_thread(unsigned char * tx) {

    k_msgq_put(&crypto_queue,&tx,K_FOREVER);

    return 0;

}

int send_cipher_via_uart(unsigned char * en_decrypt, unsigned char * tx) {

	return 0;

}

void * uart_in_thread(void * x) {

    state_machine();

    return x;

}

void * uart_out_thread(void * x) {

    int iLauf = 0;
    struct uart_message * message;

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
            while(iLauf < message->len) {
                // printk("%sWriting <%c> = <%i>%s\n", COLOR_RED, message[iLauf], message[iLauf], RESET_COLOR);
                uart_poll_out(uart_dev,message->message[iLauf++]);
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
// See https://github.com/intel/tinycrypt

void cbc_mode(const struct device *dev, uint8_t en_decrypt) {

	uint32_t in_buffer_len = buffer_length + (en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? 0 : 16);
	uint32_t out_buffer_len = buffer_length + (en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? 16 : 0);

	g_out_buffer = malloc(out_buffer_len);

	struct cipher_ctx ini = {
		.keylen = AES_KEY_LEN,
		.key.bit_stream = g_key,
		.flags = cap_flags,
	};
	struct cipher_pkt buffers = {
		.in_buf = g_in_buffer,
		.in_len = in_buffer_len,
		.out_buf_max = out_buffer_len,
		.out_buf = g_out_buffer,
	};

	if (cipher_begin_session(
		crypto_dev,
		&ini,
		CRYPTO_CIPHER_ALGO_AES,
		CRYPTO_CIPHER_MODE_CBC,
		en_decrypt)) {
	 		send_string_via_uart(ERROR_MESSAGE);
			goto cleanup;
	}

    print_data("Key : ", "%02X", g_key, AES_KEY_LEN);
    print_data("IV : ", "%02X", g_iv_key, AES_KEY_LEN);
    print_data(
		"Input-Buffer : ",
		(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? "%c" : "%02X"),
		g_in_buffer,
		in_buffer_len
	);

	if (cipher_cbc_op(
		&ini,
		&buffers,
		((en_decrypt == CRYPTO_CIPHER_OP_DECRYPT) ? g_in_buffer : g_iv_key))) {
		send_string_via_uart(ERROR_MESSAGE);
		LOG_ERR("CBC mode failed");
		goto cleanup;
	}
    print_data(
		"CBC-Output-Buffer : ",
		(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? "%02X" : "%c"),
		g_out_buffer,
		out_buffer_len
	);

cleanup:
	cipher_free_session(dev, &ini);
}

void * process_thread(void * x) {

    char * message = "";
	struct uart_message message;

    while(1) {

        #if ALIVE_MESSAGES == TRUE
            sleep(1);
            printk("%sProcessing-Thread is alive%s \n", COLOR_BLUE, RESET_COLOR);
        #endif

        // Block until Data is available
        if(!k_msgq_get(&crypto_queue,&message,K_NO_WAIT)) {

            printk("%sProcessing Thread received : <%c> %s \n", COLOR_RED, message[0], RESET_COLOR);

            switch (message[0]) {
                case ENCRYPT_CHAR:
                    processing_thread_state = ST_BUSY;
                    cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_ENCRYPT);
                    processing_thread_state = ST_INIT;
                    break;
                case DECRYPT_CHAR:
                    processing_thread_state = ST_BUSY;
                    cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_DECRYPT);
					send_string_via_uart(ENCRYPT_STRING);
					message = {message: g_out_buffer, len: strlen(g_out_buffer)}
                    send_string_via_uart(message);
                    processing_thread_state = ST_INIT;
                    break;
                case PROCESSING_CHAR:
                    processing_thread_state = ST_BUSY;
                    send_string_via_uart(PROCESSING_MESSAGE);
                    processing_thread_state = ST_INIT;
                    break;
                case WAIT_CHAR:
                    processing_thread_state = ST_BUSY;
                    sleep(5);
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
    const unsigned char *title,
    const unsigned char *formatter,
    const void* data,
    int len
){

	printk("%s\"",title);

	const unsigned char * p = (const unsigned char *) data;
	int i = 0;

	for (; i<len; ++i)
		printk(formatter, *(p++));

	printk("\"\n");

}
