#ifndef STMWRAP_H
#define STMWRAP_H

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/cm3/scs.h>
#include <libopencm3/cm3/dwt.h>
#include <libopencm3/stm32/flash.h>

#ifdef STM32F4
#include <libopencm3/stm32/rng.h>
#endif

void clock_setup(void);
void gpio_setup(void);
void usart_setup(int baud);
void send_USART_str(const char* in);
void send_USART_bytes(const unsigned char* in, int n);

#endif
