
32BIT=native_posix
64BIT=native_posix_64
BOARD=$(64BIT)

PRJ_DIR=code/
ABS_PRJ_DIR=$(abspath $(PRJ_DIR))
SOURCE_DIR=src/
SOURCE_FILES=$(wildcard $(PRJ_DIR)/*.*) $(wildcard $(PRJ_DIR)/*/*.*)

ZEPHYR_HOME=~/zephyrproject/zephyr/
BUILD_DIR=$(ZEPHYR_HOME)build
EXEC_OUT=$(ZEPHYR_HOME)/build/zephyr/zephyr.elf
EXEC_OPTIONS=-attach_uart_cmd="xterm -e screen /dev/pts/4 &"

all: $(EXEC_OUT)
	@$(MAKE) -s -C $(ZEPHYR_HOME) build
	@$(MAKE) -s run

$(EXEC_OUT): $(SOURCE_FILES)
	@echo "Building Project"
	@cd $(ZEPHYR_HOME) && west build -p auto -b $(BOARD) $(ABS_PRJ_DIR)
	@echo "west build -p auto -b $(BOARD) $(ABS_PRJ_DIR)"

run: $(EXEC_OUT)
	@echo "Running Project"
	$(EXEC_OUT) $(EXEC_OPTIONS)

config:
	@cd $(ZEPHYR_HOME) && west build -t menuconfig

# ------------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR);
