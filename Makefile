
#Select Board
32BIT=native_posix
64BIT=native_posix_64
ifeq ("$(BOARD)","32")
BOARD_VAR=$(32BIT)
else
BOARD_VAR=$(64BIT)
endif

# Select Test-Suite using CMD => "make test -j2 TEST=1"
ifeq ("$(TEST)","0")
TEST_SUITE=MyTests.test_00_connection_alive
else ifeq ("$(TEST)","1")
TEST_SUITE=MyTests.test_01_availibility
else ifeq ("$(TEST)","2")
TEST_SUITE=MyTests.test_02_blocking
else ifeq ("$(TEST)","3")
TEST_SUITE=MyTests.test_03_decrypt_fault
else ifeq ("$(TEST)","4")
TEST_SUITE=MyTests.test_04_decrypt_defaults
else ifeq ("$(TEST)","5")
TEST_SUITE=MyTests.test_05_decrypt_key_iv
else
TEST_SUITE=
endif

# Setup Code specific Paths
PRJ_DIR=code/
ABS_PRJ_DIR=$(abspath $(PRJ_DIR))
SOURCE_DIR=src/
# Create List of Files that impact the Executable
SOURCE_FILES=$(wildcard $(PRJ_DIR)/*.*) $(wildcard $(PRJ_DIR)/*/*.*)

# Setup Zephyr specific Paths
ZEPHYR_HOME=~/zephyrproject/zephyr/
BUILD_DIR=$(ZEPHYR_HOME)build
EXEC_OUT=$(ZEPHYR_HOME)build/zephyr/zephyr.elf
TEST_SCRIPT=$(abspath test.py)
UART_PTY=/dev/pts/0
TEST_COMMAND=python3 $(TEST_SCRIPT) $(TEST_SUITE) -v $(UART_PTY)

# Build Executable
all: $(EXEC_OUT)
	@$(MAKE) -s -C $(ZEPHYR_HOME) build

# Create Executable from Source-Files
$(EXEC_OUT): $(SOURCE_FILES)
	@echo "Building Project"
	@cd $(ZEPHYR_HOME) && west build -p auto -b $(BOARD_VAR) $(ABS_PRJ_DIR)
	@echo "west build -p auto -b $(BOARD_VAR) $(ABS_PRJ_DIR)"

# Run Executable and Python-Test in two seperate Threads
# They are connnected via the UART at /dev/pts/0
test: $(EXEC_OUT)
	@$(MAKE) -s run python_test -j2

# Run Executable
run: $(EXEC_OUT)
	@echo "Running Project"
	@$(EXEC_OUT) $(EXEC_OPTIONS)

# Test Python => Fails if called alone => Use "make test"
.PHONY: python_test
python_test:
	@echo "Running Test"
	@$(TEST_COMMAND)

# ------------------------------------------------------------------------------

# Clean generated Files
.PHONY: clean
clean:
	@echo "Cleaning Build-Directory"
	@rm -rf $(BUILD_DIR)
