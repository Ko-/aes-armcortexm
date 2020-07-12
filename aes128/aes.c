#include "../common/stm32wrapper.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void AES_128_keyschedule(const uint8_t *, uint8_t *);
extern void AES_128_keyschedule_dec(const uint8_t *, uint8_t *);
extern void AES_128_encrypt(const uint8_t *, const uint8_t *, uint8_t *);
extern void AES_128_decrypt(const uint8_t *, const uint8_t *, uint8_t *);

int main(void)
{
    clock_setup();
    gpio_setup();
    usart_setup(115200);

    // plainly reading from CYCCNT is more efficient than using the
    // dwt_read_cycle_counter() interface offered by libopencm3,
    // as this adds extra overhead because of the function call

    SCS_DEMCR |= SCS_DEMCR_TRCENA;
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;

    const uint8_t key[16] = {4,5,6,7,4,5,6,8,4,5,6,9,4,5,6,10};
    uint8_t in[16] = {0,0,0,0,1,2,3,1,2,4,1,2,5,1,2,6};
    uint8_t out[16];

    uint8_t rk[11*16];
    char buffer[36];

    memcpy(rk, key, 16);

    unsigned int oldcount = DWT_CYCCNT;
    AES_128_keyschedule(key, rk+16);
    unsigned int cyclecount = DWT_CYCCNT-oldcount;

/*
    // Print all round keys
    unsigned int i,j;
    for(i=0;i<11*4;++i) {
        sprintf(buffer, "rk[%2d]: ", i);
        for(j=0;j<4;++j)
            sprintf(buffer+2*j+8, "%02x", rk[i*4+j]);
        send_USART_str(buffer);
    }
*/

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

    oldcount = DWT_CYCCNT;
    AES_128_encrypt(rk, in, out);
    cyclecount = DWT_CYCCNT-oldcount;

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

/*
    // Print ciphertext
    sprintf(buffer, "out: ");
    send_USART_str(buffer);
    for(i=0;i<16;++i)
        sprintf(buffer+2*i, "%02x", out[i]);
    send_USART_str(buffer);
*/

    memcpy(rk+160, key, 16);

    oldcount = DWT_CYCCNT;
    AES_128_keyschedule_dec(key, rk);
    cyclecount = DWT_CYCCNT-oldcount;

/*
    // Print all decryption round keys
    for(i=0;i<11*4;++i) {
        sprintf(buffer, "rk[%2d]: ", i);
        for(j=0;j<4;++j)
            sprintf(buffer+2*j+8, "%02x", rk[i*4+j]);
        send_USART_str(buffer);
    }
*/

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

    oldcount = DWT_CYCCNT;
    AES_128_decrypt(rk, out, in);
    cyclecount = DWT_CYCCNT-oldcount;

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

/*
    // Print plaintext
    sprintf(buffer, "in: ");
    send_USART_str(buffer);
    for(i=0;i<16;++i)
        sprintf(buffer+2*i, "%02x", in[i]);
    send_USART_str(buffer);
*/

    while (1);

    return 0;
}
