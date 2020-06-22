#include "stm32wrapper.h"

/* 24 MHz */
const struct rcc_clock_scale myclock = {
    //HSE = 8 MHz
    .pllm = 8, //VCOin = HSE / PLLM = 1 MHz
    .plln = 192, //VCOout = VCOin * PLLN = 192 MHz
    .pllp = 8, //PLLCLK = VCOout / PLLP = 24 MHz (low to have 0WS)
    .pllq = 4, //PLL48CLK = VCOout / PLLQ = 48 MHz (required for USB, RNG)
    .hpre = RCC_CFGR_HPRE_DIV_NONE,
    .ppre1 = RCC_CFGR_PPRE_DIV_2,
    .ppre2 = RCC_CFGR_PPRE_DIV_NONE,
    .flash_config = FLASH_ACR_LATENCY_0WS,
    .apb1_frequency = 12000000,
    .apb2_frequency = 24000000,
};


void clock_setup(void)
{
    rcc_clock_setup_pll(&myclock);
    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_USART2);
    rcc_periph_clock_enable(RCC_CCMDATARAM);
#ifdef NEEDS_RNG
    rcc_periph_clock_enable(RCC_RNG);
#endif
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

void flash_setup(void)
{
    FLASH_ACR |= FLASH_ACR_ICEN;
    FLASH_ACR |= FLASH_ACR_DCEN;
    FLASH_ACR |= FLASH_ACR_PRFTEN;
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
