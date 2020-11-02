CC 		= gcc

CFLAGS 		= -Wall
LFLAGS		= -pthread -lpq -lm -lssl -lcrypto

INC_DIR		= ../inc
OBJ_DIR		= ../obj
BIN_DIR		= ../bin
SRC_DIR		= .

COAP_OBJ_DIR	= $(wildcard ../lib/libcoap/src/*.o)

INCLUDES 	= -I/usr/include/postgresql \
		  -I$(INC_DIR) \
		  #-I../lib/libcoap/include/coap2

TARGET 		= $(BIN_DIR)/gateway
#OBJS		= $(wildcard $(OBJ_DIR)/*.o)
#
SRCS		= $(wildcard $(SRC_DIR)/*.c)
OBJS		= $(patsubst $(SRC_DIR)%.c, $(OBJ_DIR)%.o, $(SRCS))
#


$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) $(COAP_OBJ_DIR) -o $(TARGET) $(LFLAGS)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c -MD $(CFLAGS) $(INCLUDES) $< -o $@

-include $(OBJ_DIR)/*.d


.PHONY: clean print

clean :
	rm -f $(BIN_DIR)/* $(OBJ_DIR)/*

print :
	$(info $$OBJS is [${OBJS}])
