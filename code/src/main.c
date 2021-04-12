
#include "main.h"

// Init Program States
static enum states prog_state = ST_INIT;
volatile static enum states processing_thread_state = ST_INIT;
static enum operations prog_operation = OP_INIT;

// Create Message-Queues using Macros created by Zephyr
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
static uint8_t * g_in_buffer;
static uint8_t * g_out_buffer;
static unsigned char * g_out_cipher_buffer;
// Create global Buffer-Length-Variable
static uint16_t buffer_length = 32;

// Create contingous IV and Key with Default-Values "BBBBBBBBBBBBBBBB"
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

static uint32_t stop_flag = FALSE;

void main(void) {

    #if ALIVE_MESSAGES == TRUE
        LOG_INF("%sMain-Thread started%s", MAIN_THREAD_COLOR, RESET_COLOR);
    #endif

	// Get Handle to the UART_0-Device
	uart_dev = device_get_binding(UART_DRV_NAME);
	// Check that the UART_0-Device-Handle is correct
	if (!uart_dev) {
        LOG_ERR("%s%s pseudo device not found!%s", ERROR_COLOR, UART_DRV_NAME, RESET_COLOR);
        return;
    }
	// Configure UART_0-Device
    if(!uart_configure(uart_dev, &uart_cfg)) {
        LOG_ERR("%sError during UART-Config!%s", ERROR_COLOR, RESET_COLOR);
        return;
    }
	// Get Handle to Crypto_Device
	crypto_dev = device_get_binding(CRYPTO_DRV_NAME);
	// Check that the Crypto-Device-Handle is correct
	if (!crypto_dev) {
        LOG_ERR("%s%s pseudo device not found!%s", ERROR_COLOR, CRYPTO_DRV_NAME, RESET_COLOR);
        return;
    }
	// Ensure that the Crypto-Device has the neccessary Hardware
	if (validate_hw_compatibility(crypto_dev)) {
            LOG_ERR("%sIncompatible Hardware!%s", ERROR_COLOR, RESET_COLOR);
            return;
    }

	// Create Array for Thread-Handles
    pthread_t threads[NUM_THREADS];
	// Start Threads and populate the threads-Array using the Handles
    init_threads(threads);

	// Keep Main-Thread alive otherwise the other Threads will be terminated
    while (!stop_flag) {

        #if ALIVE_MESSAGES == TRUE
	        LOG_INF("%sMain-Thread is alive%s \n", MAIN_THREAD_COLOR, RESET_COLOR);
        #endif

		// Sleep so other Threads won't be blocked by the Main-Thread
        sleep(SLEEP_TIME);

    }

    #if ALIVE_MESSAGES == TRUE
        LOG_INF("%sMain-Thread stopped%s", MAIN_THREAD_COLOR, RESET_COLOR);
    #endif

}

void init_threads(pthread_t * threads) {

    int ret, i;
	pthread_attr_t attr[NUM_THREADS] = {};
    void *(*thread_routines[])(void *) = {uart_in_thread,uart_out_thread,process_thread};

	for (i = 0; i < NUM_THREADS; i++) {

		ret = pthread_create(&threads[i], &attr[i], thread_routines[i], INT_TO_POINTER(i));
        if (ret != 0) {
            LOG_ERR("%sError creating Thread%s", ERROR_COLOR, RESET_COLOR);
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

	// Run until the Stop-Flag is set
    while (!stop_flag) {

        #if ALIVE_MESSAGES == TRUE
            sleep(1);
            LOG_INF("%s%s%s\n", UART_IN_COLOR, UART_IN_MESSAGE, RESET_COLOR);
        #endif

        switch (prog_state) {

            case ST_INIT:

                // Wait for incoming Traffic
                if(!uart_poll_in(uart_dev,&uart_in)){

					#if LOG_UART_IN == TRUE
	                    LOG_INF("%sReceived : <%c> = <%i>%s",
							UART_IN_COLOR,
							uart_in,
							uart_in,
							RESET_COLOR
						);
					#endif

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
                            send_string_to_processing_thread(PROCESSING_ID_STRING);
                            break;
                        case 'w':
                        case 'W':
                            send_string_to_processing_thread(WAIT_ID_STRING);
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
						// Stop-Signal
						case 's':
						case 'S':
							stop_flag = TRUE;
							break;
                        // Echo-Test
                        case '.':
                            send_message_via_uart(&POINT_MESSAGE);
                            if (processing_thread_state == ST_BUSY) {
                                send_message_via_uart(&BUSY_MESSAGE);
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
							LOG_ERR("%sError allocating Memory for Input Buffer%s", ERROR_COLOR, RESET_COLOR);
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
					#if LOG_UART_IN == TRUE
		                LOG_INF("%sBuffer-In-Data : <%s>%s",
						UART_IN_COLOR,
						buffer,
						RESET_COLOR
					);
					#endif
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
						buffer -= AES_IV_LEN;
                        prog_state = ST_OP_DECRYPT;
                        break;
                    case OP_ENCRYPT:
                        prog_state = ST_OP_ENCRYPT;
                        break;
                    default:
                        prog_state = ST_INIT;
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
                send_string_to_processing_thread(DECRYPT_ID_STRING);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            case ST_OP_ENCRYPT:
                g_in_buffer = buffer;
                send_string_to_processing_thread(ENCRYPT_ID_STRING);
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

            default:
                prog_state = ST_INIT;
                prog_operation = OP_INIT;
                break;

        }

    }

}

int send_string_via_uart(unsigned char * tx) {

	// Create Message-Struct
	static struct uart_message message;
	message.message = tx;
	message.len = strlen(tx);

	// Create Pointer to Message-Struct
	struct uart_message * message_pointer = &message;

	// Send Pointer via Message-Queue
    k_msgq_put(&message_queue,&message_pointer,K_FOREVER);

    return 0;

}

int send_message_via_uart(struct uart_message * tx) {

	// Send Pointer to Message_Queue via Message-Queue
    k_msgq_put(&message_queue,&tx,K_FOREVER);

    return 0;

}

int send_string_to_processing_thread(unsigned char * tx) {

	// Send Pointer to String via Message-Queue
	// Strings are stored as Constants using Macros
    k_msgq_put(&crypto_queue,&tx,K_FOREVER);

    return 0;

}

int send_out_buffer_via_uart(unsigned en_decrypt) {

	// Create Buffer for Encrypted data
	g_out_cipher_buffer = malloc(buffer_length + 3);

	// Create Identifier for Receiving Program
	if(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT) {
		g_out_cipher_buffer[0] = ENCRYPT_CHAR;
		g_out_cipher_buffer[1] = ' ';
	}else{
		g_out_cipher_buffer[0] = DECRYPT_CHAR;
		g_out_cipher_buffer[1] = ' ';
	}

	// Copy Crypto-Output-Buffer to Send-Buffer
	memcpy(g_out_cipher_buffer + 2, g_out_buffer, buffer_length);
	// Add Zero-Termination to Send-Buffer
	g_out_cipher_buffer[buffer_length + 2] = ZERO_CHAR;

	// Create new Message-Struct for Send-Buffer
	static struct uart_message message;
	message.message = g_out_cipher_buffer;
	message.len = buffer_length + 3;

	#if LOG_CRYPTO_CBC == TRUE
		printk("%s", UART_OUT_COLOR);
		print_data("Created CBC_Out: ", "%02X",
			g_out_cipher_buffer, buffer_length + 3);
		// Flush Output using Newline
		printk("%s\n", RESET_COLOR);
	#endif

	// Create Pointer to Message-Struct
	struct uart_message * message_pointer = &message;

	// Send Pointer to Message-Struct using Message-Queue
    k_msgq_put(&message_queue,&message_pointer,K_FOREVER);

	return 0;

}

void * uart_in_thread(void * x) {

    #if LOG_UART_IN == TRUE
		LOG_INF("%sUART-In-Thread started%s", UART_IN_COLOR, RESET_COLOR);
	#endif

    state_machine();

    #if LOG_UART_IN == TRUE
		LOG_INF("%sUART-In-Thread stopped%s", UART_IN_COLOR, RESET_COLOR);
	#endif

    return x;

}

void * uart_out_thread(void * x) {

    #if LOG_UART_OUT == TRUE
		LOG_INF("%sUART-Out-Thread started%s", UART_OUT_COLOR, RESET_COLOR);
	#endif

    int iLauf = 0;
    struct uart_message * message;
	unsigned char * temp_pointer;
	uint32_t temp_len;

	// Run until the Stop-Flag is set
    while (!stop_flag) {

        #if ALIVE_MESSAGES == TRUE
            sleep(1);
            LOG_INF("%s%s%s\n", UART_OUT_COLOR, UART_OUT_MESSAGE, RESET_COLOR);
        #endif

        // Block until Data is available
        if(!k_msgq_get(&message_queue,&message,K_NO_WAIT)) {

			// Create temporary Variables for faster access
			temp_pointer = message->message;
			temp_len = message->len;

            // Send received data via UART
            while(iLauf < temp_len) {
				uart_poll_out(uart_dev,temp_pointer[iLauf++]);
            }
            // Reset Counter
            iLauf = 0;

			#if LOG_UART_OUT == TRUE
				printk("%s", UART_OUT_COLOR);
				print_data("Uart_Out_Thread sent : ", "%02X",
					temp_pointer,
					temp_len
				);
				// Flush Output using Newline
				printk("%s\n", RESET_COLOR);
			#endif

        }

    }

    #if LOG_UART_OUT == TRUE
		LOG_INF("%sUART-Out-Thread stopped%s", UART_OUT_COLOR, RESET_COLOR);
	#endif

    return x;

}

/* -------------------------------------------------------------------------- */
/* ----- CRYPTO SECTION ----------------------------------------------------- */
/* -------------------------------------------------------------------------- */

// https://docs.zephyrproject.org/2.4.0/reference/crypto/index.html#c.cipher_ctx
// https://github.com/zephyrproject-rtos/zephyr/tree/master/drivers/crypto
// https://github.com/zephyrproject-rtos/zephyr/tree/master/samples/drivers/crypto

// Ensure that the Device has the Capabilities to encrypt using Tinycrypt
int validate_hw_compatibility(const struct device *dev) {

    uint32_t flags = 0U;

    flags = cipher_query_hwcaps(dev);
    if ((flags & CAP_RAW_KEY) == 0U) {
            LOG_ERR("%sPlease provision the key separately "
                    "as the module doesnt support a raw key%s",
					ERROR_COLOR, RESET_COLOR);
            return -1;
    }

    if ((flags & CAP_SYNC_OPS) == 0U) {
            LOG_ERR("%sThe app assumes sync semantics. "
              		"Please rewrite the app accordingly before proceeding%s",
			  		ERROR_COLOR, RESET_COLOR);
            return -1;
    }

    if ((flags & CAP_SEPARATE_IO_BUFS) == 0U) {
            LOG_ERR("%sThe app assumes distinct IO buffers. "
		            "Please rewrite the app accordingly before proceeding%s",
					ERROR_COLOR, RESET_COLOR);
            return -1;
    }

    cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;

    return 0;

}

// See https://github.com/zephyrproject-rtos/zephyr/tree/master/include/crypto
// See https://github.com/intel/tinycrypt

uint32_t cbc_mode(const struct device *dev, uint8_t en_decrypt) {

	#if LOG_CRYPTO_CBC == TRUE
		LOG_INF("%sCBC-Mode started : %s%s",
				PROCESSING_THREAD_COLOR,
				(en_decrypt ? "Encrypting" : "Decrypting"),
				RESET_COLOR);
	#endif

	uint32_t in_buffer_len = buffer_length +
		(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? 0 : 16);
	uint32_t out_buffer_len = buffer_length +
		(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? 16 : 0);
	uint32_t return_val = 0;

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
	 		send_message_via_uart(&ERROR_MESSAGE);
			return_val = -1;
			goto cleanup;
	}

	#if LOG_CRYPTO_CBC == TRUE
		printk("%s", PROCESSING_THREAD_COLOR);
	    print_data("Key : ", "%02X", g_key, AES_KEY_LEN);
		printk("\n");
	    print_data("IV : ", "%02X", g_iv_key, AES_KEY_LEN);
		printk("\n");
	    print_data(
			"Input-Buffer : ",
			(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? "%c" : "%02X"),
			g_in_buffer,
			in_buffer_len
		);
		// Flush Output using Newline
		printk("%s\n", RESET_COLOR);
	#endif

	if (cipher_cbc_op(
		&ini,
		&buffers,
		((en_decrypt == CRYPTO_CIPHER_OP_DECRYPT) ? g_in_buffer : g_iv_key))) {
			send_message_via_uart(&ERROR_MESSAGE);
			return_val = -1;
			LOG_ERR("%sCBC mode failed%s", ERROR_COLOR, RESET_COLOR);
			goto cleanup;
	}

	#if LOG_CRYPTO_CBC == TRUE
		printk("%s", PROCESSING_THREAD_COLOR);
	    print_data(
			"CBC-Output-Buffer : ",
			(en_decrypt == CRYPTO_CIPHER_OP_ENCRYPT ? "%02X" : "%c"),
			g_out_buffer,
			out_buffer_len
		);
		// Flush Output using Newline
		printk("%s\n", RESET_COLOR);
	#endif

cleanup:
	cipher_free_session(dev, &ini);

	return return_val;
}

void * process_thread(void * x) {

    #if LOG_PROCESSING_THREAD == TRUE
		LOG_INF("%sProcess-Thread started%s",
			PROCESSING_THREAD_COLOR,
			RESET_COLOR
		);
	#endif

	unsigned char * message;

	// Run until the Stop-Flag is set
    while (!stop_flag) {

        #if ALIVE_MESSAGES == TRUE
            sleep(1);
            LOG_INF("%s%s%s\n",
				COLOR_BLUE,
				PROCESSING_THREAD_MESSAGE,
				RESET_COLOR
			);
        #endif

        if(!k_msgq_get(&crypto_queue,&message,K_NO_WAIT)) {

			#if LOG_PROCESSING_THREAD == TRUE
	            LOG_INF("%sProcessing Thread received : <%c> %s \n",
					PROCESSING_THREAD_COLOR,
					message[0],
					RESET_COLOR
				);
			#endif

            switch (message[0]) {
                case ENCRYPT_CHAR:
                    processing_thread_state = ST_BUSY;
                    if(!cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_ENCRYPT)){
						send_out_buffer_via_uart(CRYPTO_CIPHER_OP_ENCRYPT);
					}
                    break;
                case DECRYPT_CHAR:
                    processing_thread_state = ST_BUSY;
                    if(!cbc_mode(crypto_dev,CRYPTO_CIPHER_OP_DECRYPT)){
						send_out_buffer_via_uart(CRYPTO_CIPHER_OP_DECRYPT);
					}
                    break;
                case PROCESSING_CHAR:
                    processing_thread_state = ST_BUSY;
                    send_message_via_uart(&PROCESSING_MESSAGE);
                    break;
                case WAIT_CHAR:
                    processing_thread_state = ST_BUSY;
                    sleep(SLEEP_TIME);
                    break;
                default:
                    break;
            }
        }else{
			processing_thread_state = ST_INIT;
		}

    }

    #if LOG_PROCESSING_THREAD == TRUE
		LOG_INF("%sProcess-Thread stopped%s",
			PROCESSING_THREAD_COLOR,
			RESET_COLOR
		);
	#endif

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

	// Create new Pointer with the right Pointer
	// so the original Pointer stays unchanged
	const unsigned char * p = (const unsigned char *) data;
	uint32_t i = 0;

	for (; i<len; ++i){
		printk(formatter, *(p++));
	}

	printk("\"");

}
