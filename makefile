# Diretórios
INCLUDES_DIR = includes
SRC_DIR = src
BUILD_DIR = build
BIN = sniffer

# Compilador e flags
CC = gcc
CFLAGS = -Wall -I$(INCLUDES_DIR)
LDFLAGS = -lpcap

# Arquivos fonte e objeto
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Regra principal
all: $(BIN)

# Compilação final do binário (na raiz do projeto)
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compilação dos objetos (.o) na pasta build/
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Limpeza
clean:
	rm -rf $(BUILD_DIR) $(BIN)

.PHONY: all clean
