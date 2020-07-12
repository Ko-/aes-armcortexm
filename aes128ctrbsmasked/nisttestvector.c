#include "../common/stm32wrapper.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct param {
    uint32_t ctr;
    uint8_t nonce[12];
    uint8_t rk[2*11*16];
} param;

extern void AES_128_keyschedule(const uint8_t *, uint8_t *);
extern void AES_128_encrypt_ctr(param const *, const uint8_t *, uint8_t *, uint32_t);
#define AES_128_decrypt_ctr AES_128_encrypt_ctr

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

#ifdef STM32F4
    RNG_CR |= RNG_CR_RNGEN;
#endif

    const uint32_t LEN = 3*16;
    const uint32_t LEN_ROUNDED = ((LEN+31)/32)*32;

    uint8_t nonce[12] = {0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t in[48] = {0};
    //const uint8_t nonce[12] = {1,2,3,1,2,4,1,2,5,1,2,6};
    //const uint8_t key[16] = {4,5,6,7,4,5,6,8,4,5,6,9,4,5,6,10};
    //uint8_t in[LEN];
    uint8_t out[LEN_ROUNDED];

    unsigned int i;
    //for(i=0;i<LEN;++i)
    //    in[i] = i%256;

    char buffer[36];
    param p;
    //p.ctr = 0;
    p.ctr = 0xf3f2f1f0;
    memcpy(p.nonce, nonce, 12);
    //memcpy(p.rk, key, 16);

    unsigned int oldcount = DWT_CYCCNT;
    AES_128_keyschedule(key, p.rk);//+16);
    unsigned int cyclecount = DWT_CYCCNT-oldcount;


    // Print all round keys
    unsigned int j;
    for(i=0;i<2*11*4;++i) {
        sprintf(buffer, "rk[%2d]: ", i);
        for(j=0;j<4;++j)
            sprintf(buffer+2*j+8, "%02x", p.rk[i*4+j]);
        send_USART_str(buffer);
    }


    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

    oldcount = DWT_CYCCNT;
    AES_128_encrypt_ctr(&p, in, out, LEN);
    cyclecount = DWT_CYCCNT-oldcount;

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);


    // Print ciphertext
    sprintf(buffer, "out: ");
    send_USART_str(buffer);
    for(i=0;i<LEN;++i) {
        sprintf(buffer+((2*i)%32), "%02x", out[i]);
        if(i%16 == 15)
            send_USART_str(buffer);
    }
    if(LEN%16 > 0)
        send_USART_str(buffer);


/*
    // Perform decryption
    p.ctr = 0;

    AES_128_decrypt_ctr(&p, out, in, LEN);

    // Print plaintext
    sprintf(buffer, "in: ");
    send_USART_str(buffer);
    for(i=0;i<LEN;++i) {
        sprintf(buffer+((2*i)%32), "%02x", in[i]);
        if(i%16 == 15)
            send_USART_str(buffer);
    }
    if(LEN%16 > 0)
        send_USART_str(buffer);
*/

    while (1);

    return 0;
}
