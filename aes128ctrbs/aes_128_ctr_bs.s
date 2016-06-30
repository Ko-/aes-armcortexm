.syntax unified

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
@ unsigned int AES_128_keyschedule(const uint8_t *key,
@       uint8_t *rk) {
.global AES_128_keyschedule
.thumb
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
@ unsigned int AES_128_encrypt_ctr(param const *p,
@       const uint8_t *in, uint8_t *out,
@       uint32_t len) {
.global AES_128_encrypt_ctr
.thumb
.type   AES_128_encrypt_ctr,%function
AES_128_encrypt_ctr:

    //function prologue, preserve registers
    push {r0-r12,r14}

    adr r14, AES_bsconst

.align 2
encrypt_blocks: //expect p in r0, AES_bsconst in r14

    //load from p two ctrnonce-blocks in r4-r7 and r8-r11
    ldmia.w r0!, {r4-r7} //increase r0 to point to p.rk for addroundkey
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7

    //increase one ctr
    add r8, #1 //won't overflow, only 2^32 blocks allowed

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

    //round 1

    //AddRoundKey
    //pop {r0} not necessary in round 1, p.rk already in r0
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0} //must push, don't want to destroy original p.rk

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move to S7-S0 = x0-x7 = r0,2,9,3,12,4,14,1 such that we're back in {r4-r11} after MixColumns
    //use r5 as tmp
    uxtb.w r12, r9
    ubfx r5, r9, #14, #2
    eor r12, r12, r5, lsl #8
    ubfx r5, r9, #8, #6
    eor r12, r12, r5, lsl #10
    ubfx r5, r9, #20, #4
    eor r12, r12, r5, lsl #16
    ubfx r5, r9, #16, #4
    eor r12, r12, r5, lsl #20
    ubfx r5, r9, #26, #6
    eor r12, r12, r5, lsl #24
    ubfx r5, r9, #24, #2
    eor r12, r12, r5, lsl #30

    uxtb.w r9, r0
    ubfx r5, r0, #14, #2
    eor r9, r9, r5, lsl #8
    ubfx r5, r0, #8, #6
    eor r9, r9, r5, lsl #10
    ubfx r5, r0, #20, #4
    eor r9, r9, r5, lsl #16
    ubfx r5, r0, #16, #4
    eor r9, r9, r5, lsl #20
    ubfx r5, r0, #26, #6
    eor r9, r9, r5, lsl #24
    ubfx r5, r0, #24, #2
    eor r9, r9, r5, lsl #30

    uxtb.w r0, r11
    ubfx r5, r11, #14, #2
    eor r0, r0, r5, lsl #8
    ubfx r5, r11, #8, #6
    eor r0, r0, r5, lsl #10
    ubfx r5, r11, #20, #4
    eor r0, r0, r5, lsl #16
    ubfx r5, r11, #16, #4
    eor r0, r0, r5, lsl #20
    ubfx r5, r11, #26, #6
    eor r0, r0, r5, lsl #24
    ubfx r5, r11, #24, #2
    eor r0, r0, r5, lsl #30

    uxtb.w r14, r3
    ubfx r5, r3, #14, #2
    eor r14, r14, r5, lsl #8
    ubfx r5, r3, #8, #6
    eor r14, r14, r5, lsl #10
    ubfx r5, r3, #20, #4
    eor r14, r14, r5, lsl #16
    ubfx r5, r3, #16, #4
    eor r14, r14, r5, lsl #20
    ubfx r5, r3, #26, #6
    eor r14, r14, r5, lsl #24
    ubfx r5, r3, #24, #2
    eor r14, r14, r5, lsl #30

    uxtb.w r3, r4
    ubfx r5, r4, #14, #2
    eor r3, r3, r5, lsl #8
    ubfx r5, r4, #8, #6
    eor r3, r3, r5, lsl #10
    ubfx r5, r4, #20, #4
    eor r3, r3, r5, lsl #16
    ubfx r5, r4, #16, #4
    eor r3, r3, r5, lsl #20
    ubfx r5, r4, #26, #6
    eor r3, r3, r5, lsl #24
    ubfx r5, r4, #24, #2
    eor r3, r3, r5, lsl #30

    uxtb.w r4, r6
    ubfx r5, r6, #14, #2
    eor r4, r4, r5, lsl #8
    ubfx r5, r6, #8, #6
    eor r4, r4, r5, lsl #10
    ubfx r5, r6, #20, #4
    eor r4, r4, r5, lsl #16
    ubfx r5, r6, #16, #4
    eor r4, r4, r5, lsl #20
    ubfx r5, r6, #26, #6
    eor r4, r4, r5, lsl #24
    ubfx r5, r6, #24, #2
    eor r4, r4, r5, lsl #30

    uxtb.w r7, r2
    ubfx r5, r2, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r2, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r2, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r2, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r2, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r2, #24, #2
    eor r2, r7, r5, lsl #30

    uxtb.w r7, r1
    ubfx r5, r1, #14, #2
    eor r7, r7, r5, lsl #8
    ubfx r5, r1, #8, #6
    eor r7, r7, r5, lsl #10
    ubfx r5, r1, #20, #4
    eor r7, r7, r5, lsl #16
    ubfx r5, r1, #16, #4
    eor r7, r7, r5, lsl #20
    ubfx r5, r1, #26, #6
    eor r7, r7, r5, lsl #24
    ubfx r5, r1, #24, #2
    eor r1, r7, r5, lsl #30

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
    pop.w {r0} //for AddRoundKey, interleaving saves 10 cycles
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
    push.w {r0}

    //SubBytes
    //Result of combining http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt with my custom instruction scheduler / register allocator
    //Note that the 4 last NOTs are moved to the key schedule
    eor  r1,  r7,  r9    //Exec y14 = U3 ^ U5; into r1
    eor  r3,  r4, r10    //Exec y13 = U0 ^ U6; into r3
    eor  r2,  r3,  r1    //Exec y12 = y13 ^ y14; into r2
    eor  r0,  r8,  r2    //Exec t1 = U4 ^ y12; into r0
    eor r14,  r0,  r9    //Exec y15 = t1 ^ U5; into r14
    and r12,  r2, r14    //Exec t2 = y12 & y15; into r12
    eor  r8, r14, r11    //Exec y6 = y15 ^ U7; into r8
    eor  r0,  r0,  r5    //Exec y20 = t1 ^ U1; into r0
    str  r2, [sp, #-4 ]  //Store r2/y12 on stack
    eor  r2,  r4,  r7    //Exec y9 = U0 ^ U3; into r2
    str  r0, [sp, #-8 ]  //Store r0/y20 on stack
    eor  r0,  r0,  r2    //Exec y11 = y20 ^ y9; into r0
    str  r2, [sp, #-12]  //Store r2/y9 on stack
    and  r2,  r2,  r0    //Exec t12 = y9 & y11; into r2
    str  r8, [sp, #-16]  //Store r8/y6 on stack
    eor  r8, r11,  r0    //Exec y7 = U7 ^ y11; into r8
    eor  r9,  r4,  r9    //Exec y8 = U0 ^ U5; into r9
    eor  r6,  r5,  r6    //Exec t0 = U1 ^ U2; into r6
    eor  r5, r14,  r6    //Exec y10 = y15 ^ t0; into r5
    str r14, [sp, #-20]  //Store r14/y15 on stack
    eor r14,  r5,  r0    //Exec y17 = y10 ^ y11; into r14
    str  r1, [sp, #-24]  //Store r1/y14 on stack
    and  r1,  r1, r14    //Exec t13 = y14 & y17; into r1
    eor  r1,  r1,  r2    //Exec t14 = t13 ^ t12; into r1
    str r14, [sp, #-28]  //Store r14/y17 on stack
    eor r14,  r5,  r9    //Exec y19 = y10 ^ y8; into r14
    str  r5, [sp, #-32]  //Store r5/y10 on stack
    and  r5,  r9,  r5    //Exec t15 = y8 & y10; into r5
    eor  r2,  r5,  r2    //Exec t16 = t15 ^ t12; into r2
    eor  r5,  r6,  r0    //Exec y16 = t0 ^ y11; into r5
    str  r0, [sp, #-36]  //Store r0/y11 on stack
    eor  r0,  r3,  r5    //Exec y21 = y13 ^ y16; into r0
    str  r3, [sp, #-40]  //Store r3/y13 on stack
    and  r3,  r3,  r5    //Exec t7 = y13 & y16; into r3
    str  r5, [sp, #-44]  //Store r5/y16 on stack
    str r11, [sp, #-48]  //Store r11/U7 on stack
    eor  r5,  r4,  r5    //Exec y18 = U0 ^ y16; into r5
    eor  r6,  r6, r11    //Exec y1 = t0 ^ U7; into r6
    eor  r7,  r6,  r7    //Exec y4 = y1 ^ U3; into r7
    and r11,  r7, r11    //Exec t5 = y4 & U7; into r11
    eor r11, r11, r12    //Exec t6 = t5 ^ t2; into r11
    eor r11, r11,  r2    //Exec t18 = t6 ^ t16; into r11
    eor r14, r11, r14    //Exec t22 = t18 ^ y19; into r14
    eor  r4,  r6,  r4    //Exec y2 = y1 ^ U0; into r4
    and r11,  r4,  r8    //Exec t10 = y2 & y7; into r11
    eor r11, r11,  r3    //Exec t11 = t10 ^ t7; into r11
    eor  r2, r11,  r2    //Exec t20 = t11 ^ t16; into r2
    eor  r2,  r2,  r5    //Exec t24 = t20 ^ y18; into r2
    eor r10,  r6, r10    //Exec y5 = y1 ^ U6; into r10
    and r11, r10,  r6    //Exec t8 = y5 & y1; into r11
    eor  r3, r11,  r3    //Exec t9 = t8 ^ t7; into r3
    eor  r3,  r3,  r1    //Exec t19 = t9 ^ t14; into r3
    eor  r3,  r3,  r0    //Exec t23 = t19 ^ y21; into r3
    eor  r0, r10,  r9    //Exec y3 = y5 ^ y8; into r0
    ldr r11, [sp, #-16]  //Load y6 into r11
    and  r5,  r0, r11    //Exec t3 = y3 & y6; into r5
    eor r12,  r5, r12    //Exec t4 = t3 ^ t2; into r12
    ldr  r5, [sp, #-8 ]  //Load y20 into r5
    str  r7, [sp, #-16]  //Store r7/y4 on stack
    eor r12, r12,  r5    //Exec t17 = t4 ^ y20; into r12
    eor  r1, r12,  r1    //Exec t21 = t17 ^ t14; into r1
    and r12,  r1,  r3    //Exec t26 = t21 & t23; into r12
    eor  r5,  r2, r12    //Exec t27 = t24 ^ t26; into r5
    eor r12, r14, r12    //Exec t31 = t22 ^ t26; into r12
    eor  r1,  r1, r14    //Exec t25 = t21 ^ t22; into r1
    and  r7,  r1,  r5    //Exec t28 = t25 & t27; into r7
    eor r14,  r7, r14    //Exec t29 = t28 ^ t22; into r14
    and  r4, r14,  r4    //Exec z14 = t29 & y2; into r4
    and  r8, r14,  r8    //Exec z5 = t29 & y7; into r8
    eor  r7,  r3,  r2    //Exec t30 = t23 ^ t24; into r7
    and r12, r12,  r7    //Exec t32 = t31 & t30; into r12
    eor r12, r12,  r2    //Exec t33 = t32 ^ t24; into r12
    eor  r7,  r5, r12    //Exec t35 = t27 ^ t33; into r7
    and  r2,  r2,  r7    //Exec t36 = t24 & t35; into r2
    eor  r5,  r5,  r2    //Exec t38 = t27 ^ t36; into r5
    and  r5, r14,  r5    //Exec t39 = t29 & t38; into r5
    eor  r1,  r1,  r5    //Exec t40 = t25 ^ t39; into r1
    eor  r5, r14,  r1    //Exec t43 = t29 ^ t40; into r5
    ldr  r7, [sp, #-44]  //Load y16 into r7
    and  r7,  r5,  r7    //Exec z3 = t43 & y16; into r7
    eor  r8,  r7,  r8    //Exec tc12 = z3 ^ z5; into r8
    str  r8, [sp, #-8 ]  //Store r8/tc12 on stack
    ldr  r8, [sp, #-40]  //Load y13 into r8
    and  r8,  r5,  r8    //Exec z12 = t43 & y13; into r8
    and r10,  r1, r10    //Exec z13 = t40 & y5; into r10
    and  r6,  r1,  r6    //Exec z4 = t40 & y1; into r6
    eor  r6,  r7,  r6    //Exec tc6 = z3 ^ z4; into r6
    eor  r3,  r3, r12    //Exec t34 = t23 ^ t33; into r3
    eor  r3,  r2,  r3    //Exec t37 = t36 ^ t34; into r3
    eor  r1,  r1,  r3    //Exec t41 = t40 ^ t37; into r1
    ldr  r5, [sp, #-32]  //Load y10 into r5
    and  r2,  r1,  r5    //Exec z8 = t41 & y10; into r2
    and  r9,  r1,  r9    //Exec z17 = t41 & y8; into r9
    str  r9, [sp, #-32]  //Store r9/z17 on stack
    eor  r5, r12,  r3    //Exec t44 = t33 ^ t37; into r5
    ldr  r7, [sp, #-20]  //Load y15 into r7
    ldr  r9, [sp, #-4 ]  //Load y12 into r9
    and  r7,  r5,  r7    //Exec z0 = t44 & y15; into r7
    and  r9,  r5,  r9    //Exec z9 = t44 & y12; into r9
    and  r0,  r3,  r0    //Exec z10 = t37 & y3; into r0
    and  r3,  r3, r11    //Exec z1 = t37 & y6; into r3
    eor  r3,  r3,  r7    //Exec tc5 = z1 ^ z0; into r3
    eor  r3,  r6,  r3    //Exec tc11 = tc6 ^ tc5; into r3
    ldr r11, [sp, #-16]  //Load y4 into r11
    ldr  r5, [sp, #-28]  //Load y17 into r5
    and r11, r12, r11    //Exec z11 = t33 & y4; into r11
    eor r14, r14, r12    //Exec t42 = t29 ^ t33; into r14
    eor  r1, r14,  r1    //Exec t45 = t42 ^ t41; into r1
    and  r5,  r1,  r5    //Exec z7 = t45 & y17; into r5
    eor  r6,  r5,  r6    //Exec tc8 = z7 ^ tc6; into r6
    ldr  r5, [sp, #-24]  //Load y14 into r5
    str  r4, [sp, #-16]  //Store r4/z14 on stack
    and  r1,  r1,  r5    //Exec z16 = t45 & y14; into r1
    ldr  r5, [sp, #-36]  //Load y11 into r5
    ldr  r4, [sp, #-12]  //Load y9 into r4
    and  r5, r14,  r5    //Exec z6 = t42 & y11; into r5
    eor  r5,  r5,  r6    //Exec tc16 = z6 ^ tc8; into r5
    and  r4, r14,  r4    //Exec z15 = t42 & y9; into r4
    eor r14,  r4,  r5    //Exec tc20 = z15 ^ tc16; into r14
    eor  r4,  r4,  r1    //Exec tc1 = z15 ^ z16; into r4
    eor  r1,  r0,  r4    //Exec tc2 = z10 ^ tc1; into r1
    eor  r0,  r1, r11    //Exec tc21 = tc2 ^ z11; into r0
    eor  r9,  r9,  r1    //Exec tc3 = z9 ^ tc2; into r9
    eor  r1,  r9,  r5    //Exec S0 = tc3 ^ tc16; into r1
    eor  r9,  r9,  r3    //Exec S3 = tc3 ^ tc11; into r9
    eor  r3,  r9,  r5    //Exec S1 = S3 ^ tc16 ^ 1; into r3
    eor r11, r10,  r4    //Exec tc13 = z13 ^ tc1; into r11
    ldr  r4, [sp, #-48]  //Load U7 into r4
    and r12, r12,  r4    //Exec z2 = t33 & U7; into r12
    eor  r7,  r7, r12    //Exec tc4 = z0 ^ z2; into r7
    eor r12,  r8,  r7    //Exec tc7 = z12 ^ tc4; into r12
    eor  r2,  r2, r12    //Exec tc9 = z8 ^ tc7; into r2
    eor  r2,  r6,  r2    //Exec tc10 = tc8 ^ tc9; into r2
    ldr  r4, [sp, #-16]  //Load z14 into r4
    eor r12,  r4,  r2    //Exec tc17 = z14 ^ tc10; into r12
    eor  r0,  r0, r12    //Exec S5 = tc21 ^ tc17; into r0
    eor  r6, r12, r14    //Exec tc26 = tc17 ^ tc20; into r6
    ldr  r4, [sp, #-32]  //Load z17 into r4
    ldr r12, [sp, #-8 ]  //Load tc12 into r12
    eor  r6,  r6,  r4    //Exec S2 = tc26 ^ z17 ^ 1; into r6
    eor r12,  r7, r12    //Exec tc14 = tc4 ^ tc12; into r12
    eor r14, r11, r12    //Exec tc18 = tc13 ^ tc14; into r14
    eor  r2,  r2, r14    //Exec S6 = tc10 ^ tc18 ^ 1; into r2
    eor r11,  r8, r14    //Exec S7 = z12 ^ tc18 ^ 1; into r11
    eor  r4, r12,  r9    //Exec S4 = tc14 ^ S3; into r4
    //[('r0', 'S5'), ('r1', 'S0'), ('r2', 'S6'), ('r3', 'S1'), ('r4', 'S4'), ('r5', 'tc16'), ('r6', 'S2'), ('r7', 'tc4'), ('r8', 'z12'), ('r9', 'S3'), ('r10', 'z13'), ('r11', 'S7'), ('r12', 'tc14'), ('r14', 'tc18')]

    //ShiftRows
    //Meanwhile move back to {r4-r11}
    //use r12 as tmp
    uxtb.w r8, r4
    ubfx r12, r4, #14, #2
    eor r8, r8, r12, lsl #8
    ubfx r12, r4, #8, #6
    eor r8, r8, r12, lsl #10
    ubfx r12, r4, #20, #4
    eor r8, r8, r12, lsl #16
    ubfx r12, r4, #16, #4
    eor r8, r8, r12, lsl #20
    ubfx r12, r4, #26, #6
    eor r8, r8, r12, lsl #24
    ubfx r12, r4, #24, #2
    eor r8, r8, r12, lsl #30

    uxtb.w r4, r1
    ubfx r12, r1, #14, #2
    eor r4, r4, r12, lsl #8
    ubfx r12, r1, #8, #6
    eor r4, r4, r12, lsl #10
    ubfx r12, r1, #20, #4
    eor r4, r4, r12, lsl #16
    ubfx r12, r1, #16, #4
    eor r4, r4, r12, lsl #20
    ubfx r12, r1, #26, #6
    eor r4, r4, r12, lsl #24
    ubfx r12, r1, #24, #2
    eor r4, r4, r12, lsl #30

    uxtb.w r5, r3
    ubfx r12, r3, #14, #2
    eor r5, r5, r12, lsl #8
    ubfx r12, r3, #8, #6
    eor r5, r5, r12, lsl #10
    ubfx r12, r3, #20, #4
    eor r5, r5, r12, lsl #16
    ubfx r12, r3, #16, #4
    eor r5, r5, r12, lsl #20
    ubfx r12, r3, #26, #6
    eor r5, r5, r12, lsl #24
    ubfx r12, r3, #24, #2
    eor r5, r5, r12, lsl #30

    uxtb.w r3, r6
    ubfx r12, r6, #14, #2
    eor r3, r3, r12, lsl #8
    ubfx r12, r6, #8, #6
    eor r3, r3, r12, lsl #10
    ubfx r12, r6, #20, #4
    eor r3, r3, r12, lsl #16
    ubfx r12, r6, #16, #4
    eor r3, r3, r12, lsl #20
    ubfx r12, r6, #26, #6
    eor r3, r3, r12, lsl #24
    ubfx r12, r6, #24, #2
    eor r6, r3, r12, lsl #30

    uxtb.w r7, r9
    ubfx r12, r9, #14, #2
    eor r7, r7, r12, lsl #8
    ubfx r12, r9, #8, #6
    eor r7, r7, r12, lsl #10
    ubfx r12, r9, #20, #4
    eor r7, r7, r12, lsl #16
    ubfx r12, r9, #16, #4
    eor r7, r7, r12, lsl #20
    ubfx r12, r9, #26, #6
    eor r7, r7, r12, lsl #24
    ubfx r12, r9, #24, #2
    eor r7, r7, r12, lsl #30

    uxtb.w r9, r0
    ubfx r12, r0, #14, #2
    eor r9, r9, r12, lsl #8
    ubfx r12, r0, #8, #6
    eor r9, r9, r12, lsl #10
    ubfx r12, r0, #20, #4
    eor r9, r9, r12, lsl #16
    ubfx r12, r0, #16, #4
    eor r9, r9, r12, lsl #20
    ubfx r12, r0, #26, #6
    eor r9, r9, r12, lsl #24
    ubfx r12, r0, #24, #2
    eor r9, r9, r12, lsl #30

    uxtb.w r10, r2
    ubfx r12, r2, #14, #2
    eor r10, r10, r12, lsl #8
    ubfx r12, r2, #8, #6
    eor r10, r10, r12, lsl #10
    ubfx r12, r2, #20, #4
    eor r10, r10, r12, lsl #16
    ubfx r12, r2, #16, #4
    eor r10, r10, r12, lsl #20
    ubfx r12, r2, #26, #6
    eor r10, r10, r12, lsl #24
    ubfx r12, r2, #24, #2
    eor r10, r10, r12, lsl #30

    uxtb.w r3, r11
    ubfx r12, r11, #14, #2
    eor r3, r3, r12, lsl #8
    ubfx r12, r11, #8, #6
    eor r3, r3, r12, lsl #10
    ubfx r12, r11, #20, #4
    eor r3, r3, r12, lsl #16
    ubfx r12, r11, #16, #4
    eor r3, r3, r12, lsl #20
    ubfx r12, r11, #26, #6
    eor r3, r3, r12, lsl #24
    ubfx r12, r11, #24, #2
    pop.w {r0}
    eor r11, r3, r12, lsl #30

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
    //push.r {r0} not necessary in final round

    //inverse transform of two blocks into non-bitsliced state
    ldr r14, =AES_bsconst //in r14, as required by encrypt_blocks

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
    ldr.w r0, [sp, #4]

    //load input, xor keystream and write to output
    ldmia r0!, {r1-r3,r12} //load first block input
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #8] //load out
    stmia.w r1!, {r4-r7} //write first block output

    ldmia r0!, {r4-r7} //load second block input
    eor r8, r4
    eor r9, r5
    eor r10, r6
    eor r11, r7
    stmia r1!, {r8-r11} //write second block output
    str r0, [sp, #4] //store in
    str r1, [sp, #8] //store out

    //load p, len, ctr
    ldr r0, [sp] //p in r0, as required by encrypt_blocks
    ldr r3, [sp, #12] //len
    ldr r4, [r0] //ctr

    //dec and store len counter
    subs r3, #32
    ble exit //if len<=0: exit
    str r3, [sp, #12]

    //inc and store ctr
    add r4, #2
    str.w r4, [r0]

    b encrypt_blocks

.align 2
exit:
    //function epilogue, restore state
    add sp, #16
    pop {r4-r12,r14}
    bx lr

