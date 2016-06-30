.PHONY: all clean

PREFIX	?= arm-none-eabi
CC		= $(PREFIX)-gcc
LD		= $(PREFIX)-gcc
OBJCOPY	= $(PREFIX)-objcopy
OBJDUMP	= $(PREFIX)-objdump
GDB		= $(PREFIX)-gdb

OPENCM3DIR = /usr/arm-none-eabi
ARMNONEEABIDIR = /usr/arm-none-eabi
COMMONDIR = ../common

all: aes_128_ctr_bs_masked_m4.bin

aes_128_ctr_bs_masked_m4.%: ARCH_FLAGS = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
aes_128_ctr_bs_masked_m4.o: CFLAGS += -DSTM32F4
$(COMMONDIR)/stm32f4_wrapper.o: CFLAGS += -DSTM32F4
aes_128_ctr_bs_masked_m4.elf: LDSCRIPT = $(COMMONDIR)/stm32f407x6.ld
aes_128_ctr_bs_masked_m4.elf: LDFLAGS += -L$(OPENCM3DIR)/lib/armv7e-m/fpu -lopencm3_stm32f4
aes_128_ctr_bs_masked_m4.elf: OBJS += $(COMMONDIR)/stm32f4_wrapper.o
aes_128_ctr_bs_masked_m4.elf: $(COMMONDIR)/stm32f4_wrapper.o $(OPENCM3DIR)/lib/libopencm3_stm32f4.a

aes_128_ctr_bs_masked_m3.%: ARCH_FLAGS = -mthumb -mcpu=cortex-m3 -msoft-float
aes_128_ctr_bs_masked_m3.o: CFLAGS += -DSTM32L1
$(COMMONDIR)/stm32l1_wrapper.o: CFLAGS += -DSTM32L1
aes_128_ctr_bs_masked_m3.elf: LDSCRIPT = $(COMMONDIR)/stm32l100xc.ld
aes_128_ctr_bs_masked_m3.elf: LDFLAGS += -L$(OPENCM3DIR)/lib/armv7-m -lopencm3_stm32l1
aes_128_ctr_bs_masked_m3.elf: OBJS += $(COMMONDIR)/stm32l1_wrapper.o
aes_128_ctr_bs_masked_m3.elf: $(COMMONDIR)/stm32l1_wrapper.o $(OPENCM3DIR)/lib/libopencm3_stm32l1.a

CFLAGS		+= -O3 \
		   -Wall -Wextra -Wimplicit-function-declaration \
		   -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		   -Wundef -Wshadow \
		   -I$(ARMNONEEABIDIR)/include -I$(OPENCM3DIR)/include \
		   -fno-common $(ARCH_FLAGS) -MD
LDFLAGS		+= --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
		   -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections,--no-print-gc-sections \
		   $(ARCH_FLAGS)

OBJS		+= aes_128_ctr_bs_masked.s

%.bin: %.elf
	$(OBJCOPY) -Obinary $^ $@

%.elf: %.o $(OBJS) $(LDSCRIPT)
	$(LD) -o $@ $< $(OBJS) $(LDFLAGS)

aes%.o: aes_128_ctr_bs_masked.c
	$(CC) $(CFLAGS) -o $@ -c $^

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f *.o *.d *.elf *.bin
