#!/usr/bin/env python3

import sys
import unittest
import serial
import time
import binascii
import signal

class TestTimeout(Exception):
    pass

class test_timeout:
    def __init__(self, seconds, error_message=None):
        if error_message is None:
            error_message = 'test timed out after {}s.'.format(seconds)
            self.seconds = seconds
            self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TestTimeout(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)

class MyTests(unittest.TestCase):
    SERDEV = '/dev/null'

    def test_00_connection_alive(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            ser.reset_input_buffer()

            # test if . characters are echoed
            for i in range(0, 10):
                ser.write(b'.')
                ser.timeout = 0.5
                reply = ser.read(2)
                self.assertEqual(reply, b'.\n')

    def test_01_availibility(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            ser.write(b'P')
            ser.timeout = 1
            reply = ser.read(100)
            self.assertEqual(reply, b"PROCESSING AVAILABLE\n")

    def test_02_blocking(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            ser.write(b'W')

            ser.write(b'P')
            ser.timeout = 1
            reply = ser.read(100)
            self.assertEqual(reply, b"")    # the first one gets queued

            with test_timeout(12):
                while True:
                    ser.write(b'.')
                    ser.timeout = 1
                    reply = ser.read(100)
                    if reply == b'.\nBUSY\n':
                        continue            # still busy

                    if reply == b".\nBUSY\nPROCESSING AVAILABLE\n":
                        break               # break loop before timeout kills us

    def test_03_decrypt_fault(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            # bad length for cipher
            cyphertext = "AAE3"
            bc = binascii.unhexlify(cyphertext) 
            data = b'D' + bytes([len(bc)]) + binascii.unhexlify(cyphertext) + b'X'

            for d in data:
                ser.write(bytes([d]))
                time.sleep(0.1)

            ser.timeout = 1
            reply = ser.read(100)
            self.assertEqual(reply, b'XERROR\n')
        

    def test_04_decrypt_defaults(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            # deciphers to "Schoene Crypto Welt" with IV=BBBBBBBBBBBBBBBB and key=BBBBBBBBBBBBBBBB aes128-cbc
            cyphertext = "AAE365272C81078AB6116B361831D0F6A5D3C8587E946B530B7957543107F15E"
            bc = binascii.unhexlify(cyphertext) 
            data = b'D' + bytes([len(bc)]) + binascii.unhexlify(cyphertext) + b'X'

            for d in data:
                ser.write(bytes([d]))
                time.sleep(0.1)

            ser.timeout = 1
            reply = ser.read(100)
            self.assertEqual(reply, b'D Schoene Crypto Welt\r\r\r\r\r\r\r\r\r\r\r\r\r\x00')

    def test_05_decrypt_key_iv(self):
        with serial.serial_for_url("spy://{}".format(self.SERDEV)) as ser:
            for d in b'KAAAAAAAAAAAAAAAAX':
                ser.write(bytes([d]))
                time.sleep(0.1)

            time.sleep(0.1)
            for d in b'IAAAAAAAAAAAAAAAAX':
                ser.write(bytes([d]))
                time.sleep(0.1)

    
            # deciphers to "Schoene Crypto Welt" with IV=BBBBBBBBBBBBBBBB and key=BBBBBBBBBBBBBBBB aes128-cbc
            cyphertext = "558F856896873142B16DC8F2EA8F334EDA7E8F7137877EC250AD733A7403CFC0"
            bc = binascii.unhexlify(cyphertext) 
            data = b'D' + bytes([len(bc)]) + binascii.unhexlify(cyphertext) + b'X'

            for d in data:
                ser.write(bytes([d]))
                time.sleep(0.1)

            ser.timeout = 1
            reply = ser.read(100)
            self.assertEqual(reply, b'D Schoene Crypto Welt\r\r\r\r\r\r\r\r\r\r\r\r\r\x00')


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Usage: test.py [unit test args] serail_device")
        print("   [unit test args] ... optional args to python unittest, i.e. -v")
        print("   serial_device .... UART_0 pseudotty of your zephyr system")
        sys.exit(1)
    else:
        MyTests.SERDEV = sys.argv.pop()
        unittest.main()

