#include "stm32wrapper.h"

/* 16 MHz */
const struct rcc_clock_scale benchmarkclock = {
    .pll_source = RCC_CFGR_PLLSRC_HSI_CLK,
    .pll_mul = RCC_CFGR_PLLMUL_MUL3,
    .pll_div = RCC_CFGR_PLLDIV_DIV3,
    .hpre = RCC_CFGR_HPRE_SYSCLK_NODIV,
    .ppre1 = RCC_CFGR_PPRE1_HCLK_NODIV,
    .ppre2 = RCC_CFGR_PPRE2_HCLK_NODIV,
    .voltage_scale = PWR_SCALE1,
    .flash_waitstates = 0,
    .ahb_frequency = 16000000,
    .apb1_frequency = 16000000,
    .apb2_frequency = 16000000,
};

void clock_setup(void)
{
    rcc_clock_setup_pll(&benchmarkclock);
    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_USART2);

    flash_64bit_enable();
    flash_prefetch_enable();
}

void gpio_setup(void)
{
    gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO2 | GPIO3);
    gpio_set_af(GPIOA, GPIO_AF7, GPIO2 | GPIO3);
}

void usart_setup(int baud)
{
    usart_set_baudrate(USART2, baud);
    usart_set_databits(USART2, 8);
    usart_set_stopbits(USART2, USART_STOPBITS_1);
    usart_set_mode(USART2, USART_MODE_TX_RX);
    usart_set_parity(USART2, USART_PARITY_NONE);
    usart_set_flow_control(USART2, USART_FLOWCONTROL_NONE);
    usart_enable(USART2);
}

void send_USART_str(const char* in)
{
    int i;
    for(i = 0; in[i] != 0; i++) {
        usart_send_blocking(USART2, (unsigned char)in[i]);
    }
    usart_send_blocking(USART2, '\r');
    usart_send_blocking(USART2, '\n');
}

void send_USART_bytes(const unsigned char* in, int n)
{
    int i;
    for(i = 0; i < n; i++) {
        usart_send_blocking(USART2, in[i]);
    }
}

