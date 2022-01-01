CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -lpcap

BUILD_DIR = build
OBJS_DIR = $(BUILD_DIR)/objs

PRECOMPILE = mkdir -p $(dir $@)
POSTCOMPILE = sleep 0

include src.mk

OBJS = $(patsubst src/%.c, $(OBJS_DIR)/%.o, $(SRC))

OBJS_ANALYZER = $(filter $(OBJS_DIR)/analyzer/%, $(OBJS))
OBJS_COMMON = $(filter $(OBJS_DIR)/common/%, $(OBJS))

all: analyzer

$(OBJS_DIR)/%.o: src/%.c Makefile
	@$(PRECOMPILE)
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(POSTCOMPILE)

analyzer: $(OBJS_COMMON) $(OBJS_ANALYZER)

analyzer:
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
		gcc $(FLAG) -I$(INC) -o $@ -c $<

clean:
			rm -rf build

fclean: clean
			rm -rf analyzer

re: fclean all

.PHONY: clean fclean re all
