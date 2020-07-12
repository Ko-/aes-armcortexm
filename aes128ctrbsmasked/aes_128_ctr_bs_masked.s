.syntax unified
.thumb

.align 2
.type AES_Sbox,%object
AES_Sbox:
.word   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
.word   0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
.word   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
.word   0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
.word   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
.word   0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
.word   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
.word   0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
.word   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
.word   0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
.word   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
.word   0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
.word   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
.word   0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
.word   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
.word   0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
.word   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
.word   0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
.word   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
.word   0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
.word   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
.word   0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
.word   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
.word   0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
.word   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
.word   0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
.word   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
.word   0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
.word   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
.word   0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
.word   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
.word   0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

.align 2
@ void AES_128_keyschedule(const uint8_t *key,
@       uint8_t *rk) {
.global AES_128_keyschedule
.type   AES_128_keyschedule,%function
AES_128_keyschedule:

    //function prologue, preserve registers
    push {r0,r4-r12,r14}

    //first we are going to expand the full key and push it to the stack
    //then we do a reversed second pass, bitslice and store to rk
    //this ensures less context switching and less loads/stores of temporary variables

    //load key
    ldm r0, {r4-r7}

    //load S-box table address once
    adr r3, AES_Sbox

    //round 1
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x01 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[4]
    eor r5, r4 //rk[5]
    eor r6, r5 //rk[6]
    eor r7, r6 //rk[7]
    push.w {r4-r7}

    //round 2
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x02 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[8]
    eor r5, r4 //rk[9]
    eor r6, r5 //rk[10]
    eor r7, r6 //rk[11]
    push.w {r4-r7}

    //round 3
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x04 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[12]
    eor r5, r4 //rk[13]
    eor r6, r5 //rk[14]
    eor r7, r6 //rk[15]
    push.w {r4-r7}

    //round 4
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x08 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[16]
    eor r5, r4 //rk[17]
    eor r6, r5 //rk[18]
    eor r7, r6 //rk[19]
    push.w {r4-r7}

    //round 5
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x10 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[20]
    eor r5, r4 //rk[21]
    eor r6, r5 //rk[22]
    eor r7, r6 //rk[23]
    push.w {r4-r7}

    //round 6
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x20 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[24]
    eor r5, r4 //rk[25]
    eor r6, r5 //rk[26]
    eor r7, r6 //rk[27]
    push.w {r4-r7}

    //round 7
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x40 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[28]
    eor r5, r4 //rk[29]
    eor r6, r5 //rk[30]
    eor r7, r6 //rk[31]
    push.w {r4-r7}

    //round 8
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x80 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[32]
    eor r5, r4 //rk[33]
    eor r6, r5 //rk[34]
    eor r7, r6 //rk[35]
    push.w {r4-r7}

    //round 9
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x1B //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[36]
    eor r5, r4 //rk[37]
    eor r6, r5 //rk[38]
    eor r7, r6 //rk[39]
    push.w {r4-r7}

    //round 10
    uxtb r8, r7, ror #8
    uxtb r9, r7, ror #16
    uxtb r10, r7, ror #24
    uxtb r11, r7

    ldr r8, [r3, r8, lsl #2]
    ldr r9, [r3, r9, lsl #2]
    ldr r10, [r3, r10, lsl #2]
    ldr r11, [r3, r11, lsl #2]

    eor r4, #0x36 //rcon
    eor r4, r8
    eor r4, r4, r9, ror #24
    eor r4, r4, r10, ror #16
    eor r4, r4, r11, ror #8 //rk[40]
    eor r5, r4 //rk[41]
    eor r6, r5 //rk[42]
    eor r7, r6 //rk[43]
    //push {r4-r7} don't have to push in last round, keep in registers

    //done expanding, now start bitslicing

    //load bsconst table address once
    adr r14, AES_bsconst

    ldm r14, {r0,r2-r3}
    //r0 = 0x55555555 (but little-endian)
    //r2 = 0x33333333
    //r3 = 0x0f0f0f0f

    //set r1 to end of rk, to be filled backwards
    add r1, #352

    //round 10
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 9
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 8
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 7
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 6
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 5
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 4
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 3
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 2
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    str r4, [r1, #-32]!

    //round 1
    pop.w {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r6, r6, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r8, r8, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r10, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r6, r4, lsl #4
    and r12, r3
    eor r6, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r5, lsl #4
    and r12, r3
    eor r7, r12
    eor r5, r5, r12, lsr #4

    eor r12, r10, r8, lsl #4
    and r12, r3
    eor r10, r12
    eor r8, r8, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r9, r9, r12, lsr #4

    //NOTs that are removed from SubBytes during encryption
    mvn r11, r11
    mvn r7, r7
    mvn r5, r5
    mvn r8, r8

    //stmdb r1!, {r4-r11} but in a different order
    //this could be fixed as we do during encryption, but then we destroy r0 and r2 and we would need to load the masks again
    str r11, [r1, #-4]
    str r7, [r1, #-8]
    str r10, [r1, #-12]
    str r6, [r1, #-16]
    str r9, [r1, #-20]
    str r5, [r1, #-24]
    str r8, [r1, #-28]
    pop {r14} //interleaving saves 1 cycle
    str r4, [r1, #-32]!

    //round 0
    ldm r14, {r4-r7} //original key
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //bitslicekey
    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r0
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r0
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r0
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r0
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r0, r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r5, r8, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r8, r6, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r2, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r8, r4, lsl #4
    and r12, r3
    eor r8, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r0, lsl #4
    and r12, r3
    eor r10, r7, r12
    eor r6, r0, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r7, r9, r12, lsr #4

    eor r12, r2, r5, lsl #4
    and r12, r3
    eor r9, r2, r12
    eor r5, r5, r12, lsr #4

    stmdb r1!, {r4-r11}

    //function epilogue, restore state
    pop {r4-r12,r14}
    bx lr

.align 2
.type AES_bsconst,%object
AES_bsconst:
.word 0xaaaaaaaa
.word 0xcccccccc
.word 0xf0f0f0f0

.align 2
@ void AES_128_encrypt_ctr(param const *p,
@       const uint8_t *in, uint8_t *out,
@       uint32_t len) {
.global AES_128_encrypt_ctr
.type   AES_128_encrypt_ctr,%function
AES_128_encrypt_ctr:

    //function prologue, preserve registers
    push {r0-r12,r14}

    adr r14, AES_bsconst
    sub sp, #1532

    //STM32F407 specific!
    //RNG_CR = 0x50060800
    //RNG_SR = 0x50060804
    //RNG_DR = 0x50060808
    movw r12, 0x0804
    movt r12, 0x5006

.align 2
encrypt_blocks: //expect p in r0, RNG_SR in r12, AES_bsconst in r14

    //generate 328 random words and store on stack
    mov.w r7, #1
    mov r4, #328
    add.w r3, sp, #216
    add r5, r12, #4 //RNG_DR
.align 2
generate_random:
    ldr r6, [r12]
    tst r6, r7
    beq generate_random //wait until RNG_SR == RNG_SR_DRDY
    ldr.w r6, [r5]
    str r6, [r3, r4, lsl #2]
    subs r4, #1
    bne generate_random

    //load from p two ctrnonce-blocks in r4-r7 and r8-r11
    ldmia.w r0!, {r4-r7} //increase r0 to point to p.rk for addroundkey
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //increase one ctr
    rev r11, r11
    add r11, #1 //won't overflow, only 2^32 blocks allowed
    rev r11, r11

    //transform state of two blocks into bitsliced form
    //general swapmoves moves {r4-r11} to {r4,8,5,9,6,10,7,11} so correct for this to have {r4-r11} again
    ldm r14, {r1-r3}
    //r1 = 0x55555555 (but little-endian)
    //r2 = 0x33333333
    //r3 = 0x0f0f0f0f

    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r1
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r9, r5, lsl #1
    and r12, r1
    eor r9, r12
    eor r5, r5, r12, lsr #1

    eor r12, r10, r6, lsl #1
    and r12, r1
    eor r10, r12
    eor r6, r6, r12, lsr #1

    eor r12, r11, r7, lsl #1
    and r12, r1
    eor r11, r12
    eor r7, r7, r12, lsr #1

    //0x33333333
    eor r12, r5, r4, lsl #2
    and r12, r2
    eor r1, r5, r12
    eor r4, r4, r12, lsr #2

    eor r12, r9, r8, lsl #2
    and r12, r2
    eor r9, r12
    eor r5, r8, r12, lsr #2

    eor r12, r7, r6, lsl #2
    and r12, r2
    eor r7, r12
    eor r8, r6, r12, lsr #2

    eor r12, r11, r10, lsl #2
    and r12, r2
    eor r11, r12
    eor r2, r10, r12, lsr #2

    //0x0f0f0f0f
    eor r12, r8, r4, lsl #4
    and r12, r3
    eor r8, r12
    eor r4, r4, r12, lsr #4

    eor r12, r7, r1, lsl #4
    and r12, r3
    eor r10, r7, r12
    eor r6, r1, r12, lsr #4

    eor r12, r11, r9, lsl #4
    and r12, r3
    eor r11, r12
    eor r7, r9, r12, lsr #4

    eor r12, r2, r5, lsl #4
    and r12, r3
    eor r9, r2, r12
    eor r5, r5, r12, lsr #4

    //mask the input data with the random words
    ldr r1, [sp, #1528]
    ldr r2, [sp, #1524]
    ldr r3, [sp, #1520]
    ldr r12, [sp, #1516]
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #1512]
    ldr r2, [sp, #1508]
    ldr r3, [sp, #1504]
    ldr r12, [sp, #1500]
    eor r8, r1
    eor r9, r2
    eor r10, r3
    eor r11, r12

    //round 1

    //AddRoundKey
    //ldr.w r0, [sp, #216] not necessary in round 1, p.rk already in r0
    ldmia r0!, {r1-r3,r12}
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldmia r0!, {r1-r3,r12}
    eor r8, r1
    eor r9, r2
    eor r10, r3
    eor r11, r12
    str.w r0, [sp, #216] //must store, don't want to destroy original p.rk

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #1496] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #1492] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #1488] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #1484] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #1480] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #1476] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #1472] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #1468] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #1464] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #1460] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #1456] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #1452] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #1448] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #1444] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #1440] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #1436] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #1432] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #1428] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #1424] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #1420] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #1416] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #1412] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #1408] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #1404] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #1400] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #1396] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #1392] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #1388] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #1420] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #1384] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #1380] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #1376] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #1380] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #1424] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #1436] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #1372] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #1376] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 2

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #1368] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #1364] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #1360] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #1356] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #1352] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #1348] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #1344] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #1340] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #1336] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #1332] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #1328] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #1324] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #1320] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #1316] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #1312] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #1308] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #1304] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #1300] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #1296] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #1292] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #1288] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #1284] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #1280] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #1276] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #1272] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #1268] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #1264] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #1260] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #1292] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #1256] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #1252] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #1248] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #1252] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #1296] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #1308] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #1244] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #1248] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 3

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #1240] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #1236] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #1232] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #1228] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #1224] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #1220] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #1216] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #1212] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #1208] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #1204] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #1200] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #1196] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #1192] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #1188] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #1184] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #1180] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #1176] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #1172] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #1168] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #1164] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #1160] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #1156] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #1152] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #1148] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #1144] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #1140] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #1136] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #1132] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #1164] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #1128] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #1124] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #1120] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #1124] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #1168] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #1180] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #1116] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #1120] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 4

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #1112] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #1108] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #1104] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #1100] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #1096] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #1092] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #1088] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #1084] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #1080] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #1076] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #1072] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #1068] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #1064] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #1060] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #1056] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #1052] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #1048] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #1044] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #1040] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #1036] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #1032] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #1028] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #1024] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #1020] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #1016] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #1012] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #1008] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #1004] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #1036] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #1000] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #996 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #992 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #996 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #1040] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #1052] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #988 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #992 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 5

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #984 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #980 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #976 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #972 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #968 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #964 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #960 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #956 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #952 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #948 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #944 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #940 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #936 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #932 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #928 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #924 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #920 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #916 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #912 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #908 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #904 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #900 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #896 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #892 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #888 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #884 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #880 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #876 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #908 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #872 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #868 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #864 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #868 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #912 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #924 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #860 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #864 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 6

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #856 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #852 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #848 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #844 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #840 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #836 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #832 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #828 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #824 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #820 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #816 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #812 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #808 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #804 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #800 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #796 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #792 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #788 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #784 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #780 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #776 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #772 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #768 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #764 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #760 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #756 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #752 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #748 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #780 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #744 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #740 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #736 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #740 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #784 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #796 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #732 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #736 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 7

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #728 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #724 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #720 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #716 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #712 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #708 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #704 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #700 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #696 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #692 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #688 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #684 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #680 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #676 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #672 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #668 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #664 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #660 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #656 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #652 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #648 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #644 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #640 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #636 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #632 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #628 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #624 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #620 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #652 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #616 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #612 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #608 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #612 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #656 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #668 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #604 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #608 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 8

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #600 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #596 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #592 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #588 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #584 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #580 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #576 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #572 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #568 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #564 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #560 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #556 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #552 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #548 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #544 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #540 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #536 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #532 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #528 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #524 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #520 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #516 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #512 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #508 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #504 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #500 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #496 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #492 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #524 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #488 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #484 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #480 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #484 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #528 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #540 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #476 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #480 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 9

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216] //write back for next round

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #472 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #468 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #464 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #460 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #456 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #452 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #448 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #444 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #440 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #436 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #432 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #428 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #424 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #420 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #416 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #412 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #408 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #404 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #400 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #396 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #392 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #388 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #384 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #380 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #376 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #372 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #368 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #364 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #396 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #360 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #356 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #352 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #356 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #400 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #412 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #348 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #352 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    eor r10, r2, r10, ror #8

    ror r4, #8
    ror r5, #8
    ror r6, #8
    ror r7, #8
    ror r8, #8
    ror r9, #8
    ror r10, #8
    ror r11, #8

    //store share on correct location for next SubBytes
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move to s7-s0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r2, r3
    ubfx r5, r3, #14, #2
    eor r2, r2, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r2, r2, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r2, r2, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r2, r2, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r2, r2, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r2, r2, r5, lsl #30

    uxtb.w r3, r1
    ubfx r5, r1, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r1, r0
    ubfx r5, r0, #14, #2
    eor r1, r1, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r1, r1, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r1, r1, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r1, r1, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r1, r1, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r1, r1, r5, lsl #30

    uxtb.w r0, r4
    ubfx r5, r4, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r4, r10
    ubfx r5, r10, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r10, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r10, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r10, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r10, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r10, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r14, r7
    ubfx r5, r7, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r7, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r7, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r7, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r7, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r7, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r9, r6
    ubfx r5, r6, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r6, r12
    ubfx r5, r12, #14, #2
    eor r6, r6, r5, lsl #8
    ubfx r5, r12, #8, #6
    eor r6, r6, r5, lsl #10
    ubfx r5, r12, #20, #4
    eor r6, r6, r5, lsl #16
    ubfx r5, r12, #16, #4
    eor r6, r6, r5, lsl #20
    ubfx r5, r12, #26, #6
    eor r6, r6, r5, lsl #24
    ubfx r5, r12, #24, #2
    eor r12, r6, r5, lsl #30

    //MixColumns
    //based on Käsper-Schwabe, squeezed in 14 registers
    //x0-x7 = r0,2,9,3,12,4,14,1, t0-t7 = r11,10,(9),8,7,6,5,(4)
    eor r11, r0, r0, ror #8

    eor r10, r2, r2, ror #8

    eor r7, r9, r9, ror #8
    eor r9, r9, r10, ror #24
    eor r9, r9, r7, ror #8

    eor r8, r3, r3, ror #8
    eor r3, r3, r7, ror #24 //r7 now free, store t4 in r7

    eor r7, r12, r12, ror #8

    eor r6, r4, r4, ror #8
    eor r4, r4, r7, ror #24

    eor r5, r14, r14, ror #8
    eor r14, r14, r6, ror #24
    eor r6, r4, r6, ror #8 //r4 now free, store t7 in r4

    eor r4, r1, r1, ror #8

    eor r0, r0, r4, ror #24
    eor r2, r2, r11, ror #24
    eor r2, r2, r4, ror #24
    eor r12, r12, r8, ror #24
    eor r3, r3, r4, ror #24
    eor r1, r1, r5, ror #24
    eor r12, r12, r4, ror #24

    eor r5, r14, r5, ror #8
    eor r4, r1, r4, ror #8
    eor r8, r3, r8, ror #8
    eor r7, r12, r7, ror #8
    eor r11, r0, r11, ror #8
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r10, r2, r10, ror #8

    //round 10

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1, r4, ror #8
    eor r5, r2, r5, ror #8
    eor r6, r3, r6, ror #8
    eor r7, r12, r7, ror #8
    ldmia r0!, {r1-r3,r12}
    eor r8, r1, r8, ror #8
    eor r9, r2, r9, ror #8
    eor r10, r3, r10, ror #8
    eor r11, r12, r11, ror #8
    str.w r0, [sp, #216]

    //SubBytes
    //Result of combining a masked version of http://www.cs.yale.edu/homes/peralta/CircuitStuff/AES_SBox.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor r12,  r7,  r9    //Exec y14m = x3m ^ x5m; into r12
    eor  r2,  r4, r10    //Exec y13m = x0m ^ x6m; into r2
    eor  r3,  r2, r12    //Exec y12m = y13m ^ y14m; into r3
    eor  r0,  r8,  r3    //Exec t1m = x4m ^ y12m; into r0
    eor  r1,  r0,  r9    //Exec y15m = t1m ^ x5m; into r1
    and r14,  r3,  r1    //Exec u6 = y12m & y15m; into r14
    eor  r8,  r1, r11    //Exec y6m = y15m ^ x7m; into r8
    eor  r0,  r0,  r5    //Exec y20m = t1m ^ x1m; into r0
    str r12, [sp, #212 ] //Store r12/y14m on stack
    eor r12,  r4,  r7    //Exec y9m = x0m ^ x3m; into r12
    str.w r0, [sp, #208 ] //Store r0/y20m on stack
    str r12, [sp, #204 ] //Store r12/y9m on stack
    eor  r0,  r0, r12    //Exec y11m = y20m ^ y9m; into r0
    eor r12, r11,  r0    //Exec y7m = x7m ^ y11m; into r12
    eor  r9,  r4,  r9    //Exec y8m = x0m ^ x5m; into r9
    eor  r5,  r5,  r6    //Exec t0m = x1m ^ x2m; into r5
    eor  r6,  r1,  r5    //Exec y10m = y15m ^ t0m; into r6
    str r12, [sp, #200 ] //Store r12/y7m on stack
    str.w r6, [sp, #196 ] //Store r6/y10m on stack
    eor r12,  r6,  r0    //Exec y17m = y10m ^ y11m; into r12
    eor  r6,  r6,  r9    //Exec y19m = y10m ^ y8m; into r6
    str.w r6, [sp, #192 ] //Store r6/y19m on stack
    str r12, [sp, #188 ] //Store r12/y17m on stack
    eor  r6,  r5,  r0    //Exec y16m = t0m ^ y11m; into r6
    eor r12,  r2,  r6    //Exec y21m = y13m ^ y16m; into r12
    str r12, [sp, #184 ] //Store r12/y21m on stack
    eor r12,  r4,  r6    //Exec y18m = x0m ^ y16m; into r12
    eor  r5,  r5, r11    //Exec y1m = t0m ^ x7m; into r5
    eor  r7,  r5,  r7    //Exec y4m = y1m ^ x3m; into r7
    eor  r4,  r5,  r4    //Exec y2m = y1m ^ x0m; into r4
    eor r10,  r5, r10    //Exec y5m = y1m ^ x6m; into r10
    str r12, [sp, #180 ] //Store r12/y18m on stack
    str  r9, [sp, #176 ] //Store r9/y8m on stack
    str  r0, [sp, #172 ] //Store r0/y11m on stack
    str  r4, [sp, #168 ] //Store r4/y2m on stack
    str r10, [sp, #164 ] //Store r10/y5m on stack
    str  r5, [sp, #160 ] //Store r5/y1m on stack
    str  r2, [sp, #152 ] //Store r2/y13m on stack
    eor r12, r10,  r9    //Exec y3m = y5m ^ y8m; into r12
    ldr  r9, [sp, #1524] //Load x1 into r9
    ldr  r0, [sp, #1520] //Load x2 into r0
    ldr  r4, [sp, #1500] //Load x7 into r4
    ldr  r5, [sp, #1504] //Load x6 into r5
    ldr  r2, [sp, #1516] //Load x3 into r2
    str  r6, [sp, #156 ] //Store r6/y16m on stack
    str  r7, [sp, #144 ] //Store r7/y4m on stack
    eor  r0,  r9,  r0    //Exec t0 = x1 ^ x2; into r0
    eor r10,  r0,  r4    //Exec y1 = t0 ^ x7; into r10
    str r10, [sp, #148 ] //Store r10/y1 on stack
    eor  r6, r10,  r5    //Exec y5 = y1 ^ x6; into r6
    eor r10, r10,  r2    //Exec y4 = y1 ^ x3; into r10
    ldr  r7, [sp, #1528] //Load x0 into r7
    str r11, [sp, #140 ] //Store r11/x7m on stack
    eor  r5,  r7,  r5    //Exec y13 = x0 ^ x6; into r5
    ldr r11, [sp, #1508] //Load x5 into r11
    str r10, [sp, #136 ] //Store r10/y4 on stack
    eor r10,  r2, r11    //Exec y14 = x3 ^ x5; into r10
    str r10, [sp, #132 ] //Store r10/y14 on stack
    str  r1, [sp, #128 ] //Store r1/y15m on stack
    str  r5, [sp, #124 ] //Store r5/y13 on stack
    eor r10,  r5, r10    //Exec y12 = y13 ^ y14; into r10
    and  r1, r10,  r1    //Exec u2 = y12 & y15m; into r1
    ldr  r5, [sp, #1512] //Load x4 into r5
    str r12, [sp, #120 ] //Store r12/y3m on stack
    str r10, [sp, #116 ] //Store r10/y12 on stack
    str  r8, [sp, #112 ] //Store r8/y6m on stack
    eor  r5,  r5, r10    //Exec t1 = x4 ^ y12; into r5
    eor r12,  r5, r11    //Exec y15 = t1 ^ x5; into r12
    and r10, r10, r12    //Exec u0 = y12 & y15; into r10
    eor  r8, r12,  r0    //Exec y10 = y15 ^ t0; into r8
    str.w r3, [sp, #108 ] //Store r3/y12m on stack
    str r12, [sp, #104 ] //Store r12/y15 on stack
    and  r3,  r3, r12    //Exec u4 = y12m & y15; into r3
    eor r12, r12,  r4    //Exec y6 = y15 ^ x7; into r12
    eor  r5,  r5,  r9    //Exec y20 = t1 ^ x1; into r5
    eor r11,  r7, r11    //Exec y8 = x0 ^ x5; into r11
    eor  r9,  r6, r11    //Exec y3 = y5 ^ y8; into r9
    eor  r2,  r7,  r2    //Exec y9 = x0 ^ x3; into r2
    str r11, [sp, #100 ] //Store r11/y8 on stack
    str  r8, [sp, #96  ] //Store r8/y10 on stack
    str.w r5, [sp, #92  ] //Store r5/y20 on stack
    eor r11,  r5,  r2    //Exec y11 = y20 ^ y9; into r11
    eor  r8,  r8, r11    //Exec y17 = y10 ^ y11; into r8
    eor  r0,  r0, r11    //Exec y16 = t0 ^ y11; into r0
    str  r8, [sp, #88  ] //Store r8/y17 on stack
    eor  r5,  r4, r11    //Exec y7 = x7 ^ y11; into r5
    ldr  r8, [sp, #344 ] //Exec t2 = rand() % 2; into r8
    str  r9, [sp, #84  ] //Store r9/y3 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t2; into r10
    eor  r1, r10,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r3,  r1,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3, r14    //Exec t2m = u5 ^ u6; into r3
    and  r1,  r9, r12    //Exec u0 = y3 & y6; into r1
    ldr r10, [sp, #112 ] //Load y6m into r10
    str r12, [sp, #80  ] //Store r12/y6 on stack
    and r14,  r9, r10    //Exec u2 = y3 & y6m; into r14
    ldr  r9, [sp, #120 ] //Load y3m into r9
    and r12,  r9, r12    //Exec u4 = y3m & y6; into r12
    and  r9,  r9, r10    //Exec u6 = y3m & y6m; into r9
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    ldr r10, [sp, #340 ] //Exec t3 = rand() % 2; into r10
    eor  r1,  r1, r10    //Exec u1 = u0 ^ t3; into r1
    eor  r1,  r1,  r9    //Exec t3m = u5 ^ u6; into r1
    eor r12, r10,  r8    //Exec t4 = t3 ^ t2; into r12
    str r12, [sp, #64  ] //Store r12/t4 on stack
    eor  r1,  r1,  r3    //Exec t4m = t3m ^ t2m; into r1
    ldr r10, [sp, #136 ] //Load y4 into r10
    ldr  r9, [sp, #140 ] //Load x7m into r9
    ldr r12, [sp, #144 ] //Load y4m into r12
    and r14, r10,  r4    //Exec u0 = y4 & x7; into r14
    and r10, r10,  r9    //Exec u2 = y4 & x7m; into r10
    and  r4, r12,  r4    //Exec u4 = y4m & x7; into r4
    and r12, r12,  r9    //Exec u6 = y4m & x7m; into r12
    ldr  r9, [sp, #336 ] //Exec t5 = rand() % 2; into r9
    str.w r6, [sp, #28  ] //Store r6/y5 on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ t5; into r14
    eor r10, r14, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4, r12    //Exec t5m = u5 ^ u6; into r4
    eor  r4,  r4,  r3    //Exec t6m = t5m ^ t2m; into r4
    eor  r3,  r9,  r8    //Exec t6 = t5 ^ t2; into r3
    str.w r3, [sp, #44  ] //Store r3/t6 on stack
    ldr r12, [sp, #124 ] //Load y13 into r12
    ldr  r8, [sp, #152 ] //Load y13m into r8
    ldr  r3, [sp, #156 ] //Load y16m into r3
    str  r0, [sp, #48  ] //Store r0/y16 on stack
    and r10, r12,  r0    //Exec u0 = y13 & y16; into r10
    eor r14, r12,  r0    //Exec y21 = y13 ^ y16; into r14
    and  r9,  r8,  r0    //Exec u4 = y13m & y16; into r9
    eor  r0,  r7,  r0    //Exec y18 = x0 ^ y16; into r0
    and r12, r12,  r3    //Exec u2 = y13 & y16m; into r12
    and  r8,  r8,  r3    //Exec u6 = y13m & y16m; into r8
    ldr.w r3, [sp, #332 ] //Exec t7 = rand() % 2; into r3
    str.w r0, [sp, #24  ] //Store r0/y18 on stack
    eor r10, r10,  r3    //Exec u1 = u0 ^ t7; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor r12, r12,  r9    //Exec u5 = u3 ^ u4; into r12
    eor r12, r12,  r8    //Exec t7m = u5 ^ u6; into r12
    ldr  r8, [sp, #160 ] //Load y1m into r8
    ldr  r9, [sp, #148 ] //Load y1 into r9
    str.w r4, [sp, #20  ] //Store r4/t6m on stack
    and r10,  r6,  r8    //Exec u2 = y5 & y1m; into r10
    and  r6,  r6,  r9    //Exec u0 = y5 & y1; into r6
    ldr.w r0, [sp, #164 ] //Load y5m into r0
    and  r4,  r0,  r9    //Exec u4 = y5m & y1; into r4
    eor  r7,  r9,  r7    //Exec y2 = y1 ^ x0; into r7
    and  r0,  r0,  r8    //Exec u6 = y5m & y1m; into r0
    ldr.w r8, [sp, #328 ] //Exec t8 = rand() % 2; into r8
    str.w r7, [sp, #8   ] //Store r7/y2 on stack
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ t8; into r6
    eor r10,  r6, r10    //Exec u3 = u1 ^ u2; into r10
    eor  r4, r10,  r4    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r0    //Exec t8m = u5 ^ u6; into r4
    eor  r4,  r4, r12    //Exec t9m = t8m ^ t7m; into r4
    eor  r0,  r8,  r3    //Exec t9 = t8 ^ t7; into r0
    and r10,  r7,  r5    //Exec u0 = y2 & y7; into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r5, [sp, #4   ] //Store r5/y7 on stack
    and  r6,  r7,  r8    //Exec u2 = y2 & y7m; into r6
    ldr  r7, [sp, #168 ] //Load y2m into r7
    str  r2, [sp, #16  ] //Store r2/y9 on stack
    and  r5,  r7,  r5    //Exec u4 = y2m & y7; into r5
    and  r7,  r7,  r8    //Exec u6 = y2m & y7m; into r7
    ldr  r8, [sp, #324 ] //Exec t10 = rand() % 2; into r8
    str r11, [sp, #40  ] //Store r11/y11 on stack
    eor r10, r10,  r8    //Exec u1 = u0 ^ t10; into r10
    eor r10, r10,  r6    //Exec u3 = u1 ^ u2; into r10
    eor  r5, r10,  r5    //Exec u5 = u3 ^ u4; into r5
    eor  r7,  r5,  r7    //Exec t10m = u5 ^ u6; into r7
    eor  r7,  r7, r12    //Exec t11m = t10m ^ t7m; into r7
    eor  r5,  r8,  r3    //Exec t11 = t10 ^ t7; into r5
    and  r3,  r2, r11    //Exec u0 = y9 & y11; into r3
    ldr r12, [sp, #172 ] //Load y11m into r12
    ldr  r8, [sp, #204 ] //Load y9m into r8
    and r10,  r2, r12    //Exec u2 = y9 & y11m; into r10
    and  r2,  r8, r11    //Exec u4 = y9m & y11; into r2
    and  r8,  r8, r12    //Exec u6 = y9m & y11m; into r8
    ldr r12, [sp, #320 ] //Exec t12 = rand() % 2; into r12
    eor  r3,  r3, r12    //Exec u1 = u0 ^ t12; into r3
    eor  r3,  r3, r10    //Exec u3 = u1 ^ u2; into r3
    eor  r2,  r3,  r2    //Exec u5 = u3 ^ u4; into r2
    eor  r2,  r2,  r8    //Exec t12m = u5 ^ u6; into r2
    ldr  r3, [sp, #132 ] //Load y14 into r3
    ldr  r8, [sp, #88  ] //Load y17 into r8
    ldr  r6, [sp, #212 ] //Load y14m into r6
    ldr r11, [sp, #188 ] //Load y17m into r11
    and r10,  r3,  r8    //Exec u0 = y14 & y17; into r10
    and  r8,  r6,  r8    //Exec u4 = y14m & y17; into r8
    and  r3,  r3, r11    //Exec u2 = y14 & y17m; into r3
    and  r6,  r6, r11    //Exec u6 = y14m & y17m; into r6
    ldr r11, [sp, #316 ] //Exec t13 = rand() % 2; into r11
    eor r10, r10, r11    //Exec u1 = u0 ^ t13; into r10
    eor  r3, r10,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3,  r8    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r6    //Exec t13m = u5 ^ u6; into r3
    eor  r3,  r3,  r2    //Exec t14m = t13m ^ t12m; into r3
    eor  r4,  r4,  r3    //Exec t19m = t9m ^ t14m; into r4
    ldr r10, [sp, #184 ] //Load y21m into r10
    ldr  r8, [sp, #208 ] //Load y20m into r8
    str  r9, [sp, #184 ] //Store r9/y1 on stack
    eor  r4,  r4, r10    //Exec t23m = t19m ^ y21m; into r4
    eor  r3,  r1,  r3    //Exec t17m = t4m ^ t14m; into r3
    eor  r3,  r3,  r8    //Exec t21m = t17m ^ y20m; into r3
    eor  r1, r11, r12    //Exec t14 = t13 ^ t12; into r1
    eor  r0,  r0,  r1    //Exec t19 = t9 ^ t14; into r0
    eor  r0,  r0, r14    //Exec t23 = t19 ^ y21; into r0
    ldr  r8, [sp, #64  ] //Load t4 into r8
    eor  r1,  r8,  r1    //Exec t17 = t4 ^ t14; into r1
    ldr  r8, [sp, #92  ] //Load y20 into r8
    eor  r1,  r1,  r8    //Exec t21 = t17 ^ y20; into r1
    ldr  r8, [sp, #100 ] //Load y8 into r8
    ldr r11, [sp, #96  ] //Load y10 into r11
    ldr.w r6, [sp, #196 ] //Load y10m into r6
    ldr  r9, [sp, #176 ] //Load y8m into r9
    str  r8, [sp, #208 ] //Store r8/y8 on stack
    and r10,  r8, r11    //Exec u0 = y8 & y10; into r10
    eor r14, r11,  r8    //Exec y19 = y10 ^ y8; into r14
    and  r8,  r8,  r6    //Exec u2 = y8 & y10m; into r8
    and r11,  r9, r11    //Exec u4 = y8m & y10; into r11
    and  r9,  r9,  r6    //Exec u6 = y8m & y10m; into r9
    ldr.w  r6, [sp, #312 ] //Exec t15 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ t15; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r11, r10, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r9    //Exec t15m = u5 ^ u6; into r11
    eor  r2, r11,  r2    //Exec t16m = t15m ^ t12m; into r2
    eor  r7,  r7,  r2    //Exec t20m = t11m ^ t16m; into r7
    ldr  r8, [sp, #180 ] //Load y18m into r8
    str.w r4, [sp, #180 ] //Store r4/t23m on stack
    eor  r7,  r7,  r8    //Exec t24m = t20m ^ y18m; into r7
    eor r11,  r4,  r7    //Exec t30m = t23m ^ t24m; into r11
    ldr  r8, [sp, #20  ] //Load t6m into r8
    eor  r2,  r8,  r2    //Exec t18m = t6m ^ t16m; into r2
    ldr  r8, [sp, #192 ] //Load y19m into r8
    str.w r0, [sp, #192 ] //Store r0/t23 on stack
    eor  r2,  r2,  r8    //Exec t22m = t18m ^ y19m; into r2
    eor r10,  r3,  r2    //Exec t25m = t21m ^ t22m; into r10
    eor r12,  r6, r12    //Exec t16 = t15 ^ t12; into r12
    eor  r5,  r5, r12    //Exec t20 = t11 ^ t16; into r5
    ldr  r8, [sp, #24  ] //Load y18 into r8
    eor  r5,  r5,  r8    //Exec t24 = t20 ^ y18; into r5
    eor  r6,  r0,  r5    //Exec t30 = t23 ^ t24; into r6
    ldr  r8, [sp, #44  ] //Load t6 into r8
    str r10, [sp, #24  ] //Store r10/t25m on stack
    eor r12,  r8, r12    //Exec t18 = t6 ^ t16; into r12
    eor r12, r12, r14    //Exec t22 = t18 ^ y19; into r12
    eor r14,  r1, r12    //Exec t25 = t21 ^ t22; into r14
    and  r8,  r1,  r0    //Exec u0 = t21 & t23; into r8
    and  r1,  r1,  r4    //Exec u2 = t21 & t23m; into r1
    and  r9,  r3,  r0    //Exec u4 = t21m & t23; into r9
    and  r3,  r3,  r4    //Exec u6 = t21m & t23m; into r3
    ldr.w  r0, [sp, #308 ] //Exec t26 = rand() % 2; into r0
    str r14, [sp, #44  ] //Store r14/t25 on stack
    eor  r8,  r8,  r0    //Exec u1 = u0 ^ t26; into r8
    eor  r1,  r8,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1,  r9    //Exec u5 = u3 ^ u4; into r1
    eor  r3,  r1,  r3    //Exec t26m = u5 ^ u6; into r3
    eor  r1,  r2,  r3    //Exec t31m = t22m ^ t26m; into r1
    eor  r3,  r7,  r3    //Exec t27m = t24m ^ t26m; into r3
    and  r8, r14,  r3    //Exec u2 = t25 & t27m; into r8
    and  r9, r10,  r3    //Exec u6 = t25m & t27m; into r9
    eor  r4,  r5,  r0    //Exec t27 = t24 ^ t26; into r4
    and r14, r14,  r4    //Exec u0 = t25 & t27; into r14
    and r10, r10,  r4    //Exec u4 = t25m & t27; into r10
    str.w  r4, [sp, #20  ] //Store r4/t27 on stack
    eor  r0, r12,  r0    //Exec t31 = t22 ^ t26; into r0
    ldr.w  r4, [sp, #304 ] //Exec t28 = rand() % 2; into r4
    eor r14, r14,  r4    //Exec u1 = u0 ^ t28; into r14
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    eor r10, r14, r10    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r9    //Exec t28m = u5 ^ u6; into r10
    eor  r2, r10,  r2    //Exec t29m = t28m ^ t22m; into r2
    eor  r4,  r4, r12    //Exec t29 = t28 ^ t22; into r4
    and r12,  r0,  r6    //Exec u0 = t31 & t30; into r12
    and  r0,  r0, r11    //Exec u2 = t31 & t30m; into r0
    and r10,  r1,  r6    //Exec u4 = t31m & t30; into r10
    and  r1,  r1, r11    //Exec u6 = t31m & t30m; into r1
    ldr r11, [sp, #300 ] //Exec t32 = rand() % 2; into r11
    eor r12, r12, r11    //Exec u1 = u0 ^ t32; into r12
    eor  r0, r12,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0, r10    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0,  r1    //Exec t32m = u5 ^ u6; into r0
    eor  r0,  r0,  r7    //Exec t33m = t32m ^ t24m; into r0
    eor  r1,  r3,  r0    //Exec t35m = t27m ^ t33m; into r1
    and r12,  r5,  r1    //Exec u2 = t24 & t35m; into r12
    and  r1,  r7,  r1    //Exec u6 = t24m & t35m; into r1
    ldr r10, [sp, #180 ] //Load t23m into r10
    eor r10, r10,  r0    //Exec t34m = t23m ^ t33m; into r10
    eor r14,  r2,  r0    //Exec t42m = t29m ^ t33m; into r14
    eor r11, r11,  r5    //Exec t33 = t32 ^ t24; into r11
    ldr.w r6, [sp, #20  ] //Load t27 into r6
    str r14, [sp, #180 ] //Store r14/t42m on stack
    eor r14,  r6, r11    //Exec t35 = t27 ^ t33; into r14
    and  r5,  r5, r14    //Exec u0 = t24 & t35; into r5
    and  r7,  r7, r14    //Exec u4 = t24m & t35; into r7
    ldr r14, [sp, #192 ] //Load t23 into r14
    str  r6, [sp, #192 ] //Store r6/t27 on stack
    eor  r6,  r4, r11    //Exec t42 = t29 ^ t33; into r6
    str  r6, [sp, #56  ] //Store r6/t42 on stack
    eor r14, r14, r11    //Exec t34 = t23 ^ t33; into r14
    ldr.w  r6, [sp, #296 ] //Exec t36 = rand() % 2; into r6
    str r11, [sp, #68  ] //Store r11/t33 on stack
    eor r14,  r6, r14    //Exec t37 = t36 ^ t34; into r14
    eor r11, r11, r14    //Exec t44 = t33 ^ t37; into r11
    eor  r5,  r5,  r6    //Exec u1 = u0 ^ t36; into r5
    eor  r5,  r5, r12    //Exec u3 = u1 ^ u2; into r5
    eor  r7,  r5,  r7    //Exec u5 = u3 ^ u4; into r7
    eor  r7,  r7,  r1    //Exec t36m = u5 ^ u6; into r7
    eor  r5,  r7, r10    //Exec t37m = t36m ^ t34m; into r5
    eor  r1,  r0,  r5    //Exec t44m = t33m ^ t37m; into r1
    eor  r7,  r3,  r7    //Exec t38m = t27m ^ t36m; into r7
    and  r3,  r4,  r7    //Exec u2 = t29 & t38m; into r3
    and  r7,  r2,  r7    //Exec u6 = t29m & t38m; into r7
    ldr r10, [sp, #192 ] //Load t27 into r10
    str.w  r0, [sp, #192 ] //Store r0/t33m on stack
    ldr.w  r0, [sp, #292 ] //Exec t39 = rand() % 2; into r0
    eor r10, r10,  r6    //Exec t38 = t27 ^ t36; into r10
    and  r6,  r4, r10    //Exec u0 = t29 & t38; into r6
    and r10,  r2, r10    //Exec u4 = t29m & t38; into r10
    eor  r6,  r6,  r0    //Exec u1 = u0 ^ t39; into r6
    eor  r3,  r6,  r3    //Exec u3 = u1 ^ u2; into r3
    eor  r3,  r3, r10    //Exec u5 = u3 ^ u4; into r3
    eor  r7,  r3,  r7    //Exec t39m = u5 ^ u6; into r7
    ldr.w  r3, [sp, #24  ] //Load t25m into r3
    ldr r12, [sp, #180 ] //Load t42m into r12
    ldr  r8, [sp, #44  ] //Load t25 into r8
    ldr  r9, [sp, #56  ] //Load t42 into r9
    str.w  r1, [sp, #0   ] //Store r1/t44m on stack
    eor  r7,  r3,  r7    //Exec t40m = t25m ^ t39m; into r7
    eor  r3,  r7,  r5    //Exec t41m = t40m ^ t37m; into r3
    eor r10, r12,  r3    //Exec t45m = t42m ^ t41m; into r10
    eor  r6,  r2,  r7    //Exec t43m = t29m ^ t40m; into r6
    eor  r0,  r8,  r0    //Exec t40 = t25 ^ t39; into r0
    eor  r8,  r0, r14    //Exec t41 = t40 ^ t37; into r8
    str.w r3, [sp, #44  ] //Store r3/t41m on stack
    str  r8, [sp, #24  ] //Store r8/t41 on stack
    str r10, [sp, #20  ] //Store r10/t45m on stack
    eor  r3,  r9,  r8    //Exec t45 = t42 ^ t41; into r3
    eor  r8,  r4,  r0    //Exec t43 = t29 ^ t40; into r8
    ldr r10, [sp, #104 ] //Load y15 into r10
    ldr r12, [sp, #128 ] //Load y15m into r12
    str.w r3, [sp, #76  ] //Store r3/t45 on stack
    and  r3,  r1, r10    //Exec u4 = t44m & y15; into r3
    str r11, [sp, #128 ] //Store r11/t44 on stack
    and  r1,  r1, r12    //Exec u6 = t44m & y15m; into r1
    and r10, r11, r10    //Exec u0 = t44 & y15; into r10
    and r12, r11, r12    //Exec u2 = t44 & y15m; into r12
    ldr r11, [sp, #288 ] //Exec z0 = rand() % 2; into r11
    str r14, [sp, #104 ] //Store r14/t37 on stack
    eor r10, r10, r11    //Exec u1 = u0 ^ z0; into r10
    eor r12, r10, r12    //Exec u3 = u1 ^ u2; into r12
    eor  r3, r12,  r3    //Exec u5 = u3 ^ u4; into r3
    eor  r3,  r3,  r1    //Exec z0m = u5 ^ u6; into r3
    ldr r12, [sp, #80  ] //Load y6 into r12
    ldr r10, [sp, #112 ] //Load y6m into r10
    str.w r5, [sp, #112 ] //Store r5/t37m on stack
    and  r1, r14, r12    //Exec u0 = t37 & y6; into r1
    and r14, r14, r10    //Exec u2 = t37 & y6m; into r14
    and r12,  r5, r12    //Exec u4 = t37m & y6; into r12
    and r10,  r5, r10    //Exec u6 = t37m & y6m; into r10
    ldr.w  r5, [sp, #284 ] //Exec z1 = rand() % 2; into r5
    eor  r1,  r1,  r5    //Exec u1 = u0 ^ z1; into r1
    eor  r1,  r1, r14    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r12    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r10    //Exec z1m = u5 ^ u6; into r1
    ldr r12, [sp, #68  ] //Load t33 into r12
    ldr r10, [sp, #1500] //Load x7 into r10
    ldr  r5, [sp, #140 ] //Load x7m into r5
    str  r1, [sp, #72  ] //Store r1/z1m on stack
    and r14, r12, r10    //Exec u0 = t33 & x7; into r14
    and  r1, r12,  r5    //Exec u2 = t33 & x7m; into r1
    ldr r12, [sp, #192 ] //Load t33m into r12
    str  r8, [sp, #60  ] //Store r8/t43 on stack
    and r10, r12, r10    //Exec u4 = t33m & x7; into r10
    and  r5, r12,  r5    //Exec u6 = t33m & x7m; into r5
    ldr r12, [sp, #280 ] //Exec z2 = rand() % 2; into r12
    str.w r0, [sp, #52  ] //Store r0/t40 on stack
    eor r14, r14, r12    //Exec u1 = u0 ^ z2; into r14
    eor  r1, r14,  r1    //Exec u3 = u1 ^ u2; into r1
    eor  r1,  r1, r10    //Exec u5 = u3 ^ u4; into r1
    eor  r5,  r1,  r5    //Exec z2m = u5 ^ u6; into r5
    ldr  r1, [sp, #48  ] //Load y16 into r1
    ldr r14, [sp, #156 ] //Load y16m into r14
    str  r6, [sp, #156 ] //Store r6/t43m on stack
    and r10,  r8,  r1    //Exec u0 = t43 & y16; into r10
    and  r8,  r8, r14    //Exec u2 = t43 & y16m; into r8
    and  r1,  r6,  r1    //Exec u4 = t43m & y16; into r1
    and r14,  r6, r14    //Exec u6 = t43m & y16m; into r14
    ldr.w  r6, [sp, #276 ] //Exec z3 = rand() % 2; into r6
    eor r10, r10,  r6    //Exec u1 = u0 ^ z3; into r10
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor  r1, r10,  r1    //Exec u5 = u3 ^ u4; into r1
    eor  r1,  r1, r14    //Exec z3m = u5 ^ u6; into r1
    eor  r3,  r3,  r1    //Exec t53m = z0m ^ z3m; into r3
    eor r11, r11,  r6    //Exec t53 = z0 ^ z3; into r11
    ldr  r8, [sp, #184 ] //Load y1 into r8
    ldr r14, [sp, #160 ] //Load y1m into r14
    str.w r7, [sp, #184 ] //Store r7/t40m on stack
    and r10,  r0,  r8    //Exec u0 = t40 & y1; into r10
    and  r0,  r0, r14    //Exec u2 = t40 & y1m; into r0
    and  r8,  r7,  r8    //Exec u4 = t40m & y1; into r8
    and r14,  r7, r14    //Exec u6 = t40m & y1m; into r14
    ldr.w  r7, [sp, #272 ] //Exec z4 = rand() % 2; into r7
    str.w r4, [sp, #160 ] //Store r4/t29 on stack
    eor r10, r10,  r7    //Exec u1 = u0 ^ z4; into r10
    eor  r0, r10,  r0    //Exec u3 = u1 ^ u2; into r0
    eor  r0,  r0,  r8    //Exec u5 = u3 ^ u4; into r0
    eor  r0,  r0, r14    //Exec z4m = u5 ^ u6; into r0
    ldr r10, [sp, #4   ] //Load y7 into r10
    ldr  r8, [sp, #200 ] //Load y7m into r8
    str.w r2, [sp, #200 ] //Store r2/t29m on stack
    and r14,  r4, r10    //Exec u0 = t29 & y7; into r14
    and  r4,  r4,  r8    //Exec u2 = t29 & y7m; into r4
    and r10,  r2, r10    //Exec u4 = t29m & y7; into r10
    and  r8,  r2,  r8    //Exec u6 = t29m & y7m; into r8
    ldr.w  r2, [sp, #268 ] //Exec z5 = rand() % 2; into r2
    eor r14, r14,  r2    //Exec u1 = u0 ^ z5; into r14
    eor  r4, r14,  r4    //Exec u3 = u1 ^ u2; into r4
    eor  r4,  r4, r10    //Exec u5 = u3 ^ u4; into r4
    eor  r4,  r4,  r8    //Exec z5m = u5 ^ u6; into r4
    eor r10,  r5,  r4    //Exec t51m = z2m ^ z5m; into r10
    str r10, [sp, #48  ] //Store r10/t51m on stack
    eor r14, r12,  r2    //Exec t51 = z2 ^ z5; into r14
    ldr  r8, [sp, #40  ] //Load y11 into r8
    ldr r10, [sp, #172 ] //Load y11m into r10
    str r14, [sp, #148 ] //Store r14/t51 on stack
    str  r9, [sp, #32  ] //Store r9/t42 on stack
    and r14,  r9,  r8    //Exec u0 = t42 & y11; into r14
    and  r9,  r9, r10    //Exec u2 = t42 & y11m; into r9
    ldr.w r2, [sp, #180 ] //Load t42m into r2
    str r11, [sp, #36  ] //Store r11/t53 on stack
    and  r8,  r2,  r8    //Exec u4 = t42m & y11; into r8
    and r10,  r2, r10    //Exec u6 = t42m & y11m; into r10
    ldr.w  r2, [sp, #264 ] //Exec z6 = rand() % 2; into r2
    str.w r4, [sp, #4   ] //Store r4/z5m on stack
    eor r14, r14,  r2    //Exec u1 = u0 ^ z6; into r14
    eor r14, r14,  r9    //Exec u3 = u1 ^ u2; into r14
    eor r14, r14,  r8    //Exec u5 = u3 ^ u4; into r14
    eor r10, r14, r10    //Exec z6m = u5 ^ u6; into r10
    ldr  r8, [sp, #76  ] //Load t45 into r8
    ldr r14, [sp, #88  ] //Load y17 into r14
    ldr.w r4, [sp, #188 ] //Load y17m into r4
    ldr r11, [sp, #20  ] //Load t45m into r11
    str  r8, [sp, #12  ] //Store r8/t45 on stack
    and  r9,  r8, r14    //Exec u0 = t45 & y17; into r9
    and  r8,  r8,  r4    //Exec u2 = t45 & y17m; into r8
    and r14, r11, r14    //Exec u4 = t45m & y17; into r14
    and  r4, r11,  r4    //Exec u6 = t45m & y17m; into r4
    ldr r11, [sp, #260 ] //Exec z7 = rand() % 2; into r11
    eor  r9,  r9, r11    //Exec u1 = u0 ^ z7; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor r14,  r8, r14    //Exec u5 = u3 ^ u4; into r14
    eor  r4, r14,  r4    //Exec z7m = u5 ^ u6; into r4
    eor r10, r10,  r4    //Exec t54m = z6m ^ z7m; into r10
    eor  r1,  r1, r10    //Exec t59m = z3m ^ t54m; into r1
    eor  r2,  r2, r11    //Exec t54 = z6 ^ z7; into r2
    eor  r2,  r6,  r2    //Exec t59 = z3 ^ t54; into r2
    eor r14,  r7,  r2    //Exec t64 = z4 ^ t59; into r14
    str r14, [sp, #88  ] //Store r14/t64 on stack
    str.w r2, [sp, #40  ] //Store r2/t59 on stack
    eor r10,  r0,  r1    //Exec t64m = z4m ^ t59m; into r10
    ldr  r8, [sp, #24  ] //Load t41 into r8
    ldr  r6, [sp, #96  ] //Load y10 into r6
    ldr r14, [sp, #196 ] //Load y10m into r14
    ldr  r2, [sp, #44  ] //Load t41m into r2
    and  r9,  r8,  r6    //Exec u0 = t41 & y10; into r9
    and  r8,  r8, r14    //Exec u2 = t41 & y10m; into r8
    and  r6,  r2,  r6    //Exec u4 = t41m & y10; into r6
    and r14,  r2, r14    //Exec u6 = t41m & y10m; into r14
    ldr.w  r2, [sp, #256 ] //Exec z8 = rand() % 2; into r2
    eor  r9,  r9,  r2    //Exec u1 = u0 ^ z8; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r14,  r6, r14    //Exec z8m = u5 ^ u6; into r14
    eor  r4,  r4, r14    //Exec t52m = z7m ^ z8m; into r4
    eor  r2, r11,  r2    //Exec t52 = z7 ^ z8; into r2
    ldr  r8, [sp, #0   ] //Load t44m into r8
    ldr r11, [sp, #116 ] //Load y12 into r11
    ldr.w r6, [sp, #108 ] //Load y12m into r6
    ldr  r9, [sp, #128 ] //Load t44 into r9
    str.w r2, [sp, #128 ] //Store r2/t52 on stack
    and r14,  r8, r11    //Exec u4 = t44m & y12; into r14
    and  r8,  r8,  r6    //Exec u6 = t44m & y12m; into r8
    and r11,  r9, r11    //Exec u0 = t44 & y12; into r11
    and  r6,  r9,  r6    //Exec u2 = t44 & y12m; into r6
    ldr  r9, [sp, #252 ] //Exec z9 = rand() % 2; into r9
    str.w r4, [sp, #108 ] //Store r4/t52m on stack
    eor r11, r11,  r9    //Exec u1 = u0 ^ z9; into r11
    eor r11, r11,  r6    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r8    //Exec z9m = u5 ^ u6; into r11
    ldr  r8, [sp, #112 ] //Load t37m into r8
    ldr.w r6, [sp, #84  ] //Load y3 into r6
    ldr  r7, [sp, #104 ] //Load t37 into r7
    ldr  r4, [sp, #120 ] //Load y3m into r4
    and  r2,  r8,  r6    //Exec u4 = t37m & y3; into r2
    and  r6,  r7,  r6    //Exec u0 = t37 & y3; into r6
    and  r7,  r7,  r4    //Exec u2 = t37 & y3m; into r7
    and  r4,  r8,  r4    //Exec u6 = t37m & y3m; into r4
    ldr  r8, [sp, #248 ] //Exec z10 = rand() % 2; into r8
    eor  r6,  r6,  r8    //Exec u1 = u0 ^ z10; into r6
    eor  r7,  r6,  r7    //Exec u3 = u1 ^ u2; into r7
    eor  r7,  r7,  r2    //Exec u5 = u3 ^ u4; into r7
    eor  r4,  r7,  r4    //Exec z10m = u5 ^ u6; into r4
    eor  r7, r11,  r4    //Exec t49m = z9m ^ z10m; into r7
    eor  r2,  r9,  r8    //Exec t49 = z9 ^ z10; into r2
    ldr r11, [sp, #68  ] //Load t33 into r11
    ldr r14, [sp, #136 ] //Load y4 into r14
    ldr  r9, [sp, #144 ] //Load y4m into r9
    str.w r2, [sp, #120 ] //Store r2/t49 on stack
    and  r6, r11, r14    //Exec u0 = t33 & y4; into r6
    and r11, r11,  r9    //Exec u2 = t33 & y4m; into r11
    ldr.w r2, [sp, #192 ] //Load t33m into r2
    and r14,  r2, r14    //Exec u4 = t33m & y4; into r14
    and  r2,  r2,  r9    //Exec u6 = t33m & y4m; into r2
    ldr  r9, [sp, #244 ] //Exec z11 = rand() % 2; into r9
    eor  r6,  r6,  r9    //Exec u1 = u0 ^ z11; into r6
    eor r11,  r6, r11    //Exec u3 = u1 ^ u2; into r11
    eor r11, r11, r14    //Exec u5 = u3 ^ u4; into r11
    eor  r2, r11,  r2    //Exec z11m = u5 ^ u6; into r2
    eor  r4,  r4,  r2    //Exec t47m = z10m ^ z11m; into r4
    eor  r2,  r8,  r9    //Exec t47 = z10 ^ z11; into r2
    ldr  r8, [sp, #60  ] //Load t43 into r8
    ldr r11, [sp, #124 ] //Load y13 into r11
    ldr.w r6, [sp, #152 ] //Load y13m into r6
    ldr  r9, [sp, #156 ] //Load t43m into r9
    str.w r2, [sp, #192 ] //Store r2/t47 on stack
    and r14,  r8, r11    //Exec u0 = t43 & y13; into r14
    and  r8,  r8,  r6    //Exec u2 = t43 & y13m; into r8
    and r11,  r9, r11    //Exec u4 = t43m & y13; into r11
    and  r6,  r9,  r6    //Exec u6 = t43m & y13m; into r6
    eor r14, r14,  r8    //Exec u3 = u1 ^ u2; into r14
    ldr  r9, [sp, #240 ] //Exec z12 = rand() % 2; into r9
    ldr  r8, [sp, #36  ] //Load t53 into r8
    str.w r4, [sp, #152 ] //Store r4/t47m on stack
    eor r14, r14,  r9    //Exec u1 = u0 ^ z12; into r14
    eor r11, r14, r11    //Exec u5 = u3 ^ u4; into r11
    eor r11, r11,  r6    //Exec z12m = u5 ^ u6; into r11
    eor  r5,  r5, r11    //Exec t50m = z2m ^ z12m; into r5
    eor  r5,  r5,  r3    //Exec t57m = t50m ^ t53m; into r5
    eor r12, r12,  r9    //Exec t50 = z2 ^ z12; into r12
    eor r12, r12,  r8    //Exec t57 = t50 ^ t53; into r12
    ldr r14, [sp, #52  ] //Load t40 into r14
    ldr  r6, [sp, #28  ] //Load y5 into r6
    ldr  r8, [sp, #164 ] //Load y5m into r8
    ldr  r4, [sp, #184 ] //Load t40m into r4
    and  r2, r14,  r6    //Exec u0 = t40 & y5; into r2
    and r14, r14,  r8    //Exec u2 = t40 & y5m; into r14
    and  r6,  r4,  r6    //Exec u4 = t40m & y5; into r6
    and  r4,  r4,  r8    //Exec u6 = t40m & y5m; into r4
    ldr  r8, [sp, #236 ] //Exec z13 = rand() % 2; into r8
    eor  r2,  r2,  r8    //Exec u1 = u0 ^ z13; into r2
    eor  r2,  r2, r14    //Exec u3 = u1 ^ u2; into r2
    eor  r2,  r2,  r6    //Exec u5 = u3 ^ u4; into r2
    eor  r4,  r2,  r4    //Exec z13m = u5 ^ u6; into r4
    ldr.w r2, [sp, #4   ] //Load z5m into r2
    eor  r4,  r2,  r4    //Exec t48m = z5m ^ z13m; into r4
    eor  r2, r11,  r4    //Exec t56m = z12m ^ t48m; into r2
    ldr r11, [sp, #268 ] //Load z5 into r11
    eor r11, r11,  r8    //Exec t48 = z5 ^ z13; into r11
    eor r14,  r9, r11    //Exec t56 = z12 ^ t48; into r14
    ldr  r8, [sp, #160 ] //Load t29 into r8
    ldr.w r6, [sp, #8   ] //Load y2 into r6
    str r14, [sp, #184 ] //Store r14/t56 on stack
    and  r9,  r8,  r6    //Exec u0 = t29 & y2; into r9
    ldr r14, [sp, #168 ] //Load y2m into r14
    str r11, [sp, #164 ] //Store r11/t48 on stack
    and  r8,  r8, r14    //Exec u2 = t29 & y2m; into r8
    ldr r11, [sp, #200 ] //Load t29m into r11
    str r12, [sp, #168 ] //Store r12/t57 on stack
    and  r6, r11,  r6    //Exec u4 = t29m & y2; into r6
    and r11, r11, r14    //Exec u6 = t29m & y2m; into r11
    ldr r14, [sp, #232 ] //Exec z14 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z14; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r11,  r6, r11    //Exec z14m = u5 ^ u6; into r11
    eor r11, r11,  r5    //Exec t61m = z14m ^ t57m; into r11
    eor r14, r14, r12    //Exec t61 = z14 ^ t57; into r14
    ldr  r8, [sp, #32  ] //Load t42 into r8
    ldr.w r6, [sp, #16  ] //Load y9 into r6
    str r14, [sp, #200 ] //Store r14/t61 on stack
    and  r9,  r8,  r6    //Exec u0 = t42 & y9; into r9
    ldr r14, [sp, #204 ] //Load y9m into r14
    ldr r12, [sp, #180 ] //Load t42m into r12
    str.w r2, [sp, #180 ] //Store r2/t56m on stack
    and  r8,  r8, r14    //Exec u2 = t42 & y9m; into r8
    and  r6, r12,  r6    //Exec u4 = t42m & y9; into r6
    and r12, r12, r14    //Exec u6 = t42m & y9m; into r12
    ldr r14, [sp, #228 ] //Exec z15 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z15; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor r12,  r6, r12    //Exec z15m = u5 ^ u6; into r12
    ldr  r8, [sp, #12  ] //Load t45 into r8
    ldr  r6, [sp, #132 ] //Load y14 into r6
    ldr r14, [sp, #212 ] //Load y14m into r14
    ldr  r2, [sp, #20  ] //Load t45m into r2
    and  r9,  r8,  r6    //Exec u0 = t45 & y14; into r9
    and  r8,  r8, r14    //Exec u2 = t45 & y14m; into r8
    and  r6,  r2,  r6    //Exec u4 = t45m & y14; into r6
    and  r2,  r2, r14    //Exec u6 = t45m & y14m; into r2
    ldr r14, [sp, #224 ] //Exec z16 = rand() % 2; into r14
    eor  r9,  r9, r14    //Exec u1 = u0 ^ z16; into r9
    eor  r8,  r9,  r8    //Exec u3 = u1 ^ u2; into r8
    eor  r6,  r8,  r6    //Exec u5 = u3 ^ u4; into r6
    eor  r2,  r6,  r2    //Exec z16m = u5 ^ u6; into r2
    eor r12, r12,  r2    //Exec t46m = z15m ^ z16m; into r12
    eor  r5, r12,  r5    //Exec t60m = t46m ^ t57m; into r5
    eor  r4,  r4,  r5    //Exec s7m = t48m ^ t60m; into r4
    eor  r5,  r0, r12    //Exec t58m = z4m ^ t46m; into r5
    eor  r7,  r7,  r5    //Exec t63m = t49m ^ t58m; into r7
    eor  r0,  r1,  r7    //Exec s0m = t59m ^ t63m; into r0
    ldr r12, [sp, #72  ] //Load z1m into r12
    eor  r7, r12,  r7    //Exec t66m = z1m ^ t63m; into r7
    ldr r12, [sp, #48  ] //Load t51m into r12
    eor  r1, r12,  r7    //Exec s4m = t51m ^ t66m; into r1
    eor r12,  r3,  r7    //Exec s3m = t53m ^ t66m; into r12
    eor  r7, r10, r12    //Exec s1m = t64m ^ s3m; into r7
    ldr  r3, [sp, #108 ] //Load t52m into r3
    ldr  r6, [sp, #152 ] //Load t47m into r6
    eor  r3,  r3,  r5    //Exec t62m = t52m ^ t58m; into r3
    eor  r5, r11,  r3    //Exec t65m = t61m ^ t62m; into r5
    eor  r6,  r6,  r5    //Exec s5m = t47m ^ t65m; into r6
    eor r10, r10,  r5    //Exec t67m = t64m ^ t65m; into r10
    ldr.w r5, [sp, #180 ] //Load t56m into r5
    eor  r3,  r5,  r3    //Exec s6m = t56m ^ t62m; into r3
    ldr.w  r5, [sp, #228 ] //Load z15 into r5
    str r10, [sp, #204 ] //Store r10/t67m on stack
    eor  r5,  r5, r14    //Exec t46 = z15 ^ z16; into r5
    ldr  r9, [sp, #168 ] //Load t57 into r9
    ldr  r8, [sp, #164 ] //Load t48 into r8
    str.w r2, [sp, #188 ] //Store r2/z16m on stack
    eor  r9,  r5,  r9    //Exec t60 = t46 ^ t57; into r9
    eor  r9,  r8,  r9    //Exec s7 = t48 ^ t60 ^ 1; into r9
    str  r9, [sp, #164 ] //Store r9/s7 on stack
    ldr  r9, [sp, #272 ] //Load z4 into r9
    ldr  r8, [sp, #120 ] //Load t49 into r8
    ldr r11, [sp, #40  ] //Load t59 into r11
    ldr r14, [sp, #284 ] //Load z1 into r14
    eor  r5,  r9,  r5    //Exec t58 = z4 ^ t46; into r5
    eor  r8,  r8,  r5    //Exec t63 = t49 ^ t58; into r8
    eor r11, r11,  r8    //Exec s0 = t59 ^ t63; into r11
    eor r14, r14,  r8    //Exec t66 = z1 ^ t63; into r14
    ldr  r8, [sp, #148 ] //Load t51 into r8
    ldr r10, [sp, #36  ] //Load t53 into r10
    str r11, [sp, #180 ] //Store r11/s0 on stack
    eor  r8,  r8, r14    //Exec s4 = t51 ^ t66; into r8
    eor r10, r10, r14    //Exec s3 = t53 ^ t66; into r10
    ldr r11, [sp, #88  ] //Load t64 into r11
    ldr r14, [sp, #128 ] //Load t52 into r14
    str  r8, [sp, #212 ] //Store r8/s4 on stack
    eor  r2, r11, r10    //Exec s1 = t64 ^ s3 ^ 1; into r2
    eor  r5, r14,  r5    //Exec t62 = t52 ^ t58; into r5
    ldr r14, [sp, #200 ] //Load t61 into r14
    ldr  r9, [sp, #192 ] //Load t47 into r9
    str r10, [sp, #192 ] //Store r10/s3 on stack
    eor r14, r14,  r5    //Exec t65 = t61 ^ t62; into r14
    eor  r9,  r9, r14    //Exec s5 = t47 ^ t65; into r9
    ldr r10, [sp, #88  ] //Load t64 into r10
    str  r9, [sp, #160 ] //Store r9/s5 on stack
    eor r11, r10, r14    //Exec t67 = t64 ^ t65; into r11
    ldr r8, [sp, #184 ] //Load t56 into r14
    ldr r14, [sp, #24  ] //Load t41 into r14
    ldr  r9, [sp, #208 ] //Load y8 into r9
    str.w r2, [sp, #148 ] //Store r2/s1 on stack
    eor  r8,  r8,  r5    //Exec s6 = t56 ^ t62 ^ 1; into r10
    and  r2, r14,  r9    //Exec u0 = t41 & y8; into r2
    ldr.w r5, [sp, #176 ] //Load y8m into r5
    str  r8, [sp, #200 ] //Store r10/s6 on stack
    and  r8, r14,  r5    //Exec u2 = t41 & y8m; into r8
    ldr r10, [sp, #44  ] //Load t41m into r10
    ldr r14, [sp, #220 ] //Exec z17 = rand() % 2; into r14
    and  r9, r10,  r9    //Exec u4 = t41m & y8; into r9
    and  r5, r10,  r5    //Exec u6 = t41m & y8m; into r5
    eor r10,  r2, r14    //Exec u1 = u0 ^ z17; into r2
    eor r10, r10,  r8    //Exec u3 = u1 ^ u2; into r10
    eor r10, r10,  r9    //Exec u5 = u3 ^ u4; into r10
    eor r10, r10,  r5    //Exec z17m = u5 ^ u6; into r10
    ldr  r8, [sp, #188 ] //Load z16m into r8
    ldr  r9, [sp, #204 ] //Load t67m into r9
    ldr.w  r5, [sp, #224 ] //Load z16 into r14
    eor r10,  r8, r10    //Exec t55m = z16m ^ z17m; into r10
    eor r10, r10,  r9    //Exec s2m = t55m ^ t67m; into r10
    eor r14,  r5, r14    //Exec t55 = z16 ^ z17; into r14
    eor r14, r14, r11    //Exec s2 = t55 ^ t67 ^ 1; into r14
    str r14, [sp, #208 ] //Store r14/s2 on stack
//[('r0', 's0m'), ('r1', 's4m'), ('r2', 'u0'), ('r3', 's6m'), ('r4', 's7m'), ('r5', 'z16'), ('r6', 's5m'), ('r7', 's1m'), ('r8', 'z16m'), ('r9', 'z17'), ('r10', 's2m'), ('r11', 't67'), ('r12', 's3m'), ('r14', 's2')]

    //ShiftRows
    //Meanwhile move back to {{r4-r11}}
    //use r14 as tmp
    uxtb.w r5, r7
    ubfx r14, r7, #14, #2
    eor r5, r5, r14, lsl #8
    ubfx r14, r7, #8, #6
    eor r5, r5, r14, lsl #10
    ubfx r14, r7, #20, #4
    eor r5, r5, r14, lsl #16
    ubfx r14, r7, #16, #4
    eor r5, r5, r14, lsl #20
    ubfx r14, r7, #26, #6
    eor r5, r5, r14, lsl #24
    ubfx r14, r7, #24, #2
    eor r5, r5, r14, lsl #30

    uxtb.w r7, r12
    ubfx r14, r12, #14, #2
    eor r7, r7, r14, lsl #8
    ubfx r14, r12, #8, #6
    eor r7, r7, r14, lsl #10
    ubfx r14, r12, #20, #4
    eor r7, r7, r14, lsl #16
    ubfx r14, r12, #16, #4
    eor r7, r7, r14, lsl #20
    ubfx r14, r12, #26, #6
    eor r7, r7, r14, lsl #24
    ubfx r14, r12, #24, #2
    eor r7, r7, r14, lsl #30

    uxtb.w r8, r1
    ubfx r14, r1, #14, #2
    eor r8, r8, r14, lsl #8
    ubfx r14, r1, #8, #6
    eor r8, r8, r14, lsl #10
    ubfx r14, r1, #20, #4
    eor r8, r8, r14, lsl #16
    ubfx r14, r1, #16, #4
    eor r8, r8, r14, lsl #20
    ubfx r14, r1, #26, #6
    eor r8, r8, r14, lsl #24
    ubfx r14, r1, #24, #2
    eor r8, r8, r14, lsl #30

    uxtb.w r9, r6
    ubfx r14, r6, #14, #2
    eor r9, r9, r14, lsl #8
    ubfx r14, r6, #8, #6
    eor r9, r9, r14, lsl #10
    ubfx r14, r6, #20, #4
    eor r9, r9, r14, lsl #16
    ubfx r14, r6, #16, #4
    eor r9, r9, r14, lsl #20
    ubfx r14, r6, #26, #6
    eor r9, r9, r14, lsl #24
    ubfx r14, r6, #24, #2
    eor r9, r9, r14, lsl #30

    uxtb.w r6, r10
    ubfx r14, r10, #14, #2
    eor r6, r6, r14, lsl #8
    ubfx r14, r10, #8, #6
    eor r6, r6, r14, lsl #10
    ubfx r14, r10, #20, #4
    eor r6, r6, r14, lsl #16
    ubfx r14, r10, #16, #4
    eor r6, r6, r14, lsl #20
    ubfx r14, r10, #26, #6
    eor r6, r6, r14, lsl #24
    ubfx r14, r10, #24, #2
    eor r6, r6, r14, lsl #30

    uxtb.w r10, r3
    ubfx r14, r3, #14, #2
    eor r10, r10, r14, lsl #8
    ubfx r14, r3, #8, #6
    eor r10, r10, r14, lsl #10
    ubfx r14, r3, #20, #4
    eor r10, r10, r14, lsl #16
    ubfx r14, r3, #16, #4
    eor r10, r10, r14, lsl #20
    ubfx r14, r3, #26, #6
    eor r10, r10, r14, lsl #24
    ubfx r14, r3, #24, #2
    eor r10, r10, r14, lsl #30

    uxtb.w r11, r4
    ubfx r14, r4, #14, #2
    eor r11, r11, r14, lsl #8
    ubfx r14, r4, #8, #6
    eor r11, r11, r14, lsl #10
    ubfx r14, r4, #20, #4
    eor r11, r11, r14, lsl #16
    ubfx r14, r4, #16, #4
    eor r11, r11, r14, lsl #20
    ubfx r14, r4, #26, #6
    eor r11, r11, r14, lsl #24
    ubfx r14, r4, #24, #2
    eor r11, r11, r14, lsl #30

    uxtb.w r4, r0
    ubfx r14, r0, #14, #2
    eor r4, r4, r14, lsl #8
    ubfx r14, r0, #8, #6
    eor r4, r4, r14, lsl #10
    ubfx r14, r0, #20, #4
    eor r4, r4, r14, lsl #16
    ubfx r14, r0, #16, #4
    eor r4, r4, r14, lsl #20
    ubfx r14, r0, #26, #6
    eor r4, r4, r14, lsl #24
    ubfx r14, r0, #24, #2
    eor r4, r4, r14, lsl #30

    //store share on correct location for unmasking
    str r4, [sp, #1528]
    str r5, [sp, #1524]
    str r6, [sp, #1520]
    str r7, [sp, #1516]
    str r8, [sp, #1512]
    str r9, [sp, #1508]
    str r10, [sp, #1504]
    str r11, [sp, #1500]

    //finished linear layer with one share, now do the other

    //load s\d[^m] in the positions that ShiftRows expects
    ldr r0, [sp, #180] //s0
    ldr r7, [sp, #148]
    ldr r10, [sp, #208]
    ldr r12, [sp, #192]
    ldr r1, [sp, #212]
    ldr r6, [sp, #160]
    ldr r3, [sp, #200]
    ldr r4, [sp, #164] //s7

    //ShiftRows
    //Meanwhile move back to {{r4-r11}}
    //use r14 as tmp
    uxtb.w r5, r7
    ubfx r14, r7, #14, #2
    eor r5, r5, r14, lsl #8
    ubfx r14, r7, #8, #6
    eor r5, r5, r14, lsl #10
    ubfx r14, r7, #20, #4
    eor r5, r5, r14, lsl #16
    ubfx r14, r7, #16, #4
    eor r5, r5, r14, lsl #20
    ubfx r14, r7, #26, #6
    eor r5, r5, r14, lsl #24
    ubfx r14, r7, #24, #2
    eor r5, r5, r14, lsl #30

    uxtb.w r7, r12
    ubfx r14, r12, #14, #2
    eor r7, r7, r14, lsl #8
    ubfx r14, r12, #8, #6
    eor r7, r7, r14, lsl #10
    ubfx r14, r12, #20, #4
    eor r7, r7, r14, lsl #16
    ubfx r14, r12, #16, #4
    eor r7, r7, r14, lsl #20
    ubfx r14, r12, #26, #6
    eor r7, r7, r14, lsl #24
    ubfx r14, r12, #24, #2
    eor r7, r7, r14, lsl #30

    uxtb.w r8, r1
    ubfx r14, r1, #14, #2
    eor r8, r8, r14, lsl #8
    ubfx r14, r1, #8, #6
    eor r8, r8, r14, lsl #10
    ubfx r14, r1, #20, #4
    eor r8, r8, r14, lsl #16
    ubfx r14, r1, #16, #4
    eor r8, r8, r14, lsl #20
    ubfx r14, r1, #26, #6
    eor r8, r8, r14, lsl #24
    ubfx r14, r1, #24, #2
    eor r8, r8, r14, lsl #30

    uxtb.w r9, r6
    ubfx r14, r6, #14, #2
    eor r9, r9, r14, lsl #8
    ubfx r14, r6, #8, #6
    eor r9, r9, r14, lsl #10
    ubfx r14, r6, #20, #4
    eor r9, r9, r14, lsl #16
    ubfx r14, r6, #16, #4
    eor r9, r9, r14, lsl #20
    ubfx r14, r6, #26, #6
    eor r9, r9, r14, lsl #24
    ubfx r14, r6, #24, #2
    eor r9, r9, r14, lsl #30

    uxtb.w r6, r10
    ubfx r14, r10, #14, #2
    eor r6, r6, r14, lsl #8
    ubfx r14, r10, #8, #6
    eor r6, r6, r14, lsl #10
    ubfx r14, r10, #20, #4
    eor r6, r6, r14, lsl #16
    ubfx r14, r10, #16, #4
    eor r6, r6, r14, lsl #20
    ubfx r14, r10, #26, #6
    eor r6, r6, r14, lsl #24
    ubfx r14, r10, #24, #2
    eor r6, r6, r14, lsl #30

    uxtb.w r10, r3
    ubfx r14, r3, #14, #2
    eor r10, r10, r14, lsl #8
    ubfx r14, r3, #8, #6
    eor r10, r10, r14, lsl #10
    ubfx r14, r3, #20, #4
    eor r10, r10, r14, lsl #16
    ubfx r14, r3, #16, #4
    eor r10, r10, r14, lsl #20
    ubfx r14, r3, #26, #6
    eor r10, r10, r14, lsl #24
    ubfx r14, r3, #24, #2
    eor r10, r10, r14, lsl #30

    uxtb.w r11, r4
    ubfx r14, r4, #14, #2
    eor r11, r11, r14, lsl #8
    ubfx r14, r4, #8, #6
    eor r11, r11, r14, lsl #10
    ubfx r14, r4, #20, #4
    eor r11, r11, r14, lsl #16
    ubfx r14, r4, #16, #4
    eor r11, r11, r14, lsl #20
    ubfx r14, r4, #26, #6
    eor r11, r11, r14, lsl #24
    ubfx r14, r4, #24, #2
    eor r11, r11, r14, lsl #30

    uxtb.w r4, r0
    ubfx r14, r0, #14, #2
    eor r4, r4, r14, lsl #8
    ubfx r14, r0, #8, #6
    eor r4, r4, r14, lsl #10
    ubfx r14, r0, #20, #4
    eor r4, r4, r14, lsl #16
    ubfx r14, r0, #16, #4
    eor r4, r4, r14, lsl #20
    ubfx r14, r0, #26, #6
    eor r4, r4, r14, lsl #24
    ubfx r14, r0, #24, #2
    ldr.w r0, [sp, #216] //load p.rk for AddRoundKey, interleaving saves 10 cycles
    eor r4, r4, r14, lsl #30

    //AddRoundKey
    ldmia r0!, {r1-r3,r12}
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldm r0, {r1-r3,r12}
    eor r8, r1
    eor r9, r2
    eor r10, r3
    eor r11, r12
    //str r0, [sp, #216] not necessary in final round

    //unmask the input data
    ldr r1, [sp, #1528]
    ldr r2, [sp, #1524]
    ldr r3, [sp, #1520]
    ldr r12, [sp, #1516]
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #1512]
    ldr r2, [sp, #1508]
    ldr r3, [sp, #1504]
    ldr r12, [sp, #1500]
    ldr r14, =AES_bsconst //in r14, as required by encrypt_blocks
    eor r8, r1
    eor r9, r2
    eor r10, r3
    eor r11, r12

    //inverse transform of two blocks into non-bitsliced state
    ldm r14, {r1-r3}
    //r1 = 0x33333333 (but little-endian)
    //r2 = 0x55555555
    //r3 = 0x0f0f0f0f

    //0x0f0f0f0f
    eor r12, r8, r4, lsl #4
    and r12, r3
    eor r8, r12
    eor r4, r4, r12, lsr #4

    eor r12, r10, r6, lsl #4
    and r12, r3
    eor r10, r12
    eor r6, r6, r12, lsr #4

    eor r12, r11, r7, lsl #4
    and r12, r3
    eor r11, r12
    eor r7, r7, r12, lsr #4

    eor r12, r9, r5, lsl #4
    and r12, r3
    eor r9, r12
    eor r3, r5, r12, lsr #4

    //0x33333333
    eor r12, r6, r4, lsl #2
    and r12, r2
    eor r5, r6, r12
    eor r4, r4, r12, lsr #2

    eor r12, r10, r8, lsl #2
    and r12, r2
    eor r10, r12
    eor r6, r8, r12, lsr #2

    eor r12, r7, r3, lsl #2
    and r12, r2
    eor r7, r12
    eor r8, r3, r12, lsr #2

    eor r12, r11, r9, lsl #2
    and r12, r2
    eor r11, r12
    eor r2, r9, r12, lsr #2

    //0x55555555
    eor r12, r8, r4, lsl #1
    and r12, r1
    eor r8, r12
    eor r4, r4, r12, lsr #1

    eor r12, r7, r5, lsl #1
    and r12, r1
    eor r9, r7, r12
    eor r5, r5, r12, lsr #1

    eor r12, r11, r10, lsl #1
    and r12, r1
    eor r11, r12
    eor r7, r10, r12, lsr #1

    eor r12, r2, r6, lsl #1
    and r12, r1
    eor r10, r2, r12
    eor r6, r6, r12, lsr #1

    //load in
    ldr.w r0, [sp, #1536]

    //load input, xor keystream and write to output
    ldmia r0!, {r1-r3,r12} //load first block input
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #1540] //load out
    stmia.w r1!, {r4-r7} //write first block output

    ldmia.w r0!, {r4-r7} //load second block input
    eor r8, r4
    eor r9, r5
    eor r10, r6
    eor r11, r7
    stmia r1!, {r8-r11} //write second block output
    str r0, [sp, #1536] //store in
    str r1, [sp, #1540] //store out

    //load p, len, ctr
    ldr r0, [sp, #1532] //p in r0, as required by encrypt_blocks
    ldr r3, [sp, #1544] //len
    ldr.w r4, [r0, #12] //ctr

    //dec and store len counter
    subs r3, #32
    ble exit //if len<=0: exit
    str r3, [sp, #1544]

    //inc and store ctr
    rev r4, r4
    add r4, #2
    rev r4, r4
    str.w r4, [r0, #12]

    //RNG_SR in r12, as expected by encrypt_blocks
    movw r12, 0x0804
    movt r12, 0x5006

    b encrypt_blocks

.align 2
exit:
    //function epilogue, restore state
    add sp, #1548
    pop {r4-r12,r14}
    bx lr

