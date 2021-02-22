
// int usleep(useconds_t useconds);

#include <zephyr.h>
#include <device.h>
#include <sys/printk.h>
#include <drivers/uart.h>
#include <crypto/cipher.h>
#include <crypto/cipher_structs.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
#define UART_DRV_NAME "UART_0"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);

enum states{INIT,IDLE,BUSY,AVAIL,DECRYPT,DLEN,DATA,KEY,IV,OP,OP_KEY,OP_IV,OP_DECRYPT};

int validate_hw_compatibility(const struct device *dev);
void cbc_mode(const struct device *dev);
void print_data(
    const char *title,
    const char *formatter,
    const void* data,
    int len
);

void main(void) {

	uint8_t rx_buf[10] = {0};
    uint8_t tx_buf[10] = {0x48,0x61,0x6C,0x6C,0x6F,0x21,0x20,0x20,0x20,0x0A};

	const struct device * uart_dev = device_get_binding(UART_DRV_NAME);
	if (!uart_dev) {
        LOG_ERR("%s pseudo device not found", UART_DRV_NAME);
        return;
    }
	const struct device * crypto_dev = device_get_binding(CRYPTO_DRV_NAME);
	if (!crypto_dev) {
        LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
        return;
    }

	if (validate_hw_compatibility(crypto_dev)) {
            LOG_ERR("Incompatible h/w");
            return;
    }

	cbc_mode(crypto_dev);

	while (1) {

        LOG_ERR("Error : %d %d", uart_rx_enable(uart_dev, rx_buf, 10, 50), -ENOTSUP);

		if (uart_rx_enable(uart_dev, rx_buf, 10, 50)){
            LOG_ERR("Error during UART-Receiving");
            return;
        }

		printk("Received data : <>\nSending data back\n", rx_buf);

		if(uart_tx(uart_dev,tx_buf,10,50)) {
            LOG_ERR("Error during UART-Transmission");
            return;
        }

		sleep(1);

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

    LOG_INF("CRYPTO_CAPABILITIES : %d\n", flags);

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
