# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(CRYPTO_UART)

# Get all ".c"-Files in the src-Directory
FILE(GLOB MyCSources src/*.c)
target_sources(app PRIVATE ${MyCSources})
