package org.quietkey.cardb;

/** FIPS 180-4 SHA-512 using eight-byte words, with no optional integer support. */
final class Sha512 {
    static final short SCRATCH_BYTES = 1056;
    private static final short W = 64;
    private static final short V = 704;
    private static final short TAIL = 768;
    private static final short TEMP = 1024;
    private static final byte[] INITIAL = {
        (byte) 0x6a, (byte) 0x09, (byte) 0xe6, (byte) 0x67, (byte) 0xf3, (byte) 0xbc, (byte) 0xc9, (byte) 0x08,
        (byte) 0xbb, (byte) 0x67, (byte) 0xae, (byte) 0x85, (byte) 0x84, (byte) 0xca, (byte) 0xa7, (byte) 0x3b,
        (byte) 0x3c, (byte) 0x6e, (byte) 0xf3, (byte) 0x72, (byte) 0xfe, (byte) 0x94, (byte) 0xf8, (byte) 0x2b,
        (byte) 0xa5, (byte) 0x4f, (byte) 0xf5, (byte) 0x3a, (byte) 0x5f, (byte) 0x1d, (byte) 0x36, (byte) 0xf1,
        (byte) 0x51, (byte) 0x0e, (byte) 0x52, (byte) 0x7f, (byte) 0xad, (byte) 0xe6, (byte) 0x82, (byte) 0xd1,
        (byte) 0x9b, (byte) 0x05, (byte) 0x68, (byte) 0x8c, (byte) 0x2b, (byte) 0x3e, (byte) 0x6c, (byte) 0x1f,
        (byte) 0x1f, (byte) 0x83, (byte) 0xd9, (byte) 0xab, (byte) 0xfb, (byte) 0x41, (byte) 0xbd, (byte) 0x6b,
        (byte) 0x5b, (byte) 0xe0, (byte) 0xcd, (byte) 0x19, (byte) 0x13, (byte) 0x7e, (byte) 0x21, (byte) 0x79
    };
    private static final byte[] K = {
        (byte) 0x42, (byte) 0x8a, (byte) 0x2f, (byte) 0x98, (byte) 0xd7, (byte) 0x28, (byte) 0xae, (byte) 0x22,
        (byte) 0x71, (byte) 0x37, (byte) 0x44, (byte) 0x91, (byte) 0x23, (byte) 0xef, (byte) 0x65, (byte) 0xcd,
        (byte) 0xb5, (byte) 0xc0, (byte) 0xfb, (byte) 0xcf, (byte) 0xec, (byte) 0x4d, (byte) 0x3b, (byte) 0x2f,
        (byte) 0xe9, (byte) 0xb5, (byte) 0xdb, (byte) 0xa5, (byte) 0x81, (byte) 0x89, (byte) 0xdb, (byte) 0xbc,
        (byte) 0x39, (byte) 0x56, (byte) 0xc2, (byte) 0x5b, (byte) 0xf3, (byte) 0x48, (byte) 0xb5, (byte) 0x38,
        (byte) 0x59, (byte) 0xf1, (byte) 0x11, (byte) 0xf1, (byte) 0xb6, (byte) 0x05, (byte) 0xd0, (byte) 0x19,
        (byte) 0x92, (byte) 0x3f, (byte) 0x82, (byte) 0xa4, (byte) 0xaf, (byte) 0x19, (byte) 0x4f, (byte) 0x9b,
        (byte) 0xab, (byte) 0x1c, (byte) 0x5e, (byte) 0xd5, (byte) 0xda, (byte) 0x6d, (byte) 0x81, (byte) 0x18,
        (byte) 0xd8, (byte) 0x07, (byte) 0xaa, (byte) 0x98, (byte) 0xa3, (byte) 0x03, (byte) 0x02, (byte) 0x42,
        (byte) 0x12, (byte) 0x83, (byte) 0x5b, (byte) 0x01, (byte) 0x45, (byte) 0x70, (byte) 0x6f, (byte) 0xbe,
        (byte) 0x24, (byte) 0x31, (byte) 0x85, (byte) 0xbe, (byte) 0x4e, (byte) 0xe4, (byte) 0xb2, (byte) 0x8c,
        (byte) 0x55, (byte) 0x0c, (byte) 0x7d, (byte) 0xc3, (byte) 0xd5, (byte) 0xff, (byte) 0xb4, (byte) 0xe2,
        (byte) 0x72, (byte) 0xbe, (byte) 0x5d, (byte) 0x74, (byte) 0xf2, (byte) 0x7b, (byte) 0x89, (byte) 0x6f,
        (byte) 0x80, (byte) 0xde, (byte) 0xb1, (byte) 0xfe, (byte) 0x3b, (byte) 0x16, (byte) 0x96, (byte) 0xb1,
        (byte) 0x9b, (byte) 0xdc, (byte) 0x06, (byte) 0xa7, (byte) 0x25, (byte) 0xc7, (byte) 0x12, (byte) 0x35,
        (byte) 0xc1, (byte) 0x9b, (byte) 0xf1, (byte) 0x74, (byte) 0xcf, (byte) 0x69, (byte) 0x26, (byte) 0x94,
        (byte) 0xe4, (byte) 0x9b, (byte) 0x69, (byte) 0xc1, (byte) 0x9e, (byte) 0xf1, (byte) 0x4a, (byte) 0xd2,
        (byte) 0xef, (byte) 0xbe, (byte) 0x47, (byte) 0x86, (byte) 0x38, (byte) 0x4f, (byte) 0x25, (byte) 0xe3,
        (byte) 0x0f, (byte) 0xc1, (byte) 0x9d, (byte) 0xc6, (byte) 0x8b, (byte) 0x8c, (byte) 0xd5, (byte) 0xb5,
        (byte) 0x24, (byte) 0x0c, (byte) 0xa1, (byte) 0xcc, (byte) 0x77, (byte) 0xac, (byte) 0x9c, (byte) 0x65,
        (byte) 0x2d, (byte) 0xe9, (byte) 0x2c, (byte) 0x6f, (byte) 0x59, (byte) 0x2b, (byte) 0x02, (byte) 0x75,
        (byte) 0x4a, (byte) 0x74, (byte) 0x84, (byte) 0xaa, (byte) 0x6e, (byte) 0xa6, (byte) 0xe4, (byte) 0x83,
        (byte) 0x5c, (byte) 0xb0, (byte) 0xa9, (byte) 0xdc, (byte) 0xbd, (byte) 0x41, (byte) 0xfb, (byte) 0xd4,
        (byte) 0x76, (byte) 0xf9, (byte) 0x88, (byte) 0xda, (byte) 0x83, (byte) 0x11, (byte) 0x53, (byte) 0xb5,
        (byte) 0x98, (byte) 0x3e, (byte) 0x51, (byte) 0x52, (byte) 0xee, (byte) 0x66, (byte) 0xdf, (byte) 0xab,
        (byte) 0xa8, (byte) 0x31, (byte) 0xc6, (byte) 0x6d, (byte) 0x2d, (byte) 0xb4, (byte) 0x32, (byte) 0x10,
        (byte) 0xb0, (byte) 0x03, (byte) 0x27, (byte) 0xc8, (byte) 0x98, (byte) 0xfb, (byte) 0x21, (byte) 0x3f,
        (byte) 0xbf, (byte) 0x59, (byte) 0x7f, (byte) 0xc7, (byte) 0xbe, (byte) 0xef, (byte) 0x0e, (byte) 0xe4,
        (byte) 0xc6, (byte) 0xe0, (byte) 0x0b, (byte) 0xf3, (byte) 0x3d, (byte) 0xa8, (byte) 0x8f, (byte) 0xc2,
        (byte) 0xd5, (byte) 0xa7, (byte) 0x91, (byte) 0x47, (byte) 0x93, (byte) 0x0a, (byte) 0xa7, (byte) 0x25,
        (byte) 0x06, (byte) 0xca, (byte) 0x63, (byte) 0x51, (byte) 0xe0, (byte) 0x03, (byte) 0x82, (byte) 0x6f,
        (byte) 0x14, (byte) 0x29, (byte) 0x29, (byte) 0x67, (byte) 0x0a, (byte) 0x0e, (byte) 0x6e, (byte) 0x70,
        (byte) 0x27, (byte) 0xb7, (byte) 0x0a, (byte) 0x85, (byte) 0x46, (byte) 0xd2, (byte) 0x2f, (byte) 0xfc,
        (byte) 0x2e, (byte) 0x1b, (byte) 0x21, (byte) 0x38, (byte) 0x5c, (byte) 0x26, (byte) 0xc9, (byte) 0x26,
        (byte) 0x4d, (byte) 0x2c, (byte) 0x6d, (byte) 0xfc, (byte) 0x5a, (byte) 0xc4, (byte) 0x2a, (byte) 0xed,
        (byte) 0x53, (byte) 0x38, (byte) 0x0d, (byte) 0x13, (byte) 0x9d, (byte) 0x95, (byte) 0xb3, (byte) 0xdf,
        (byte) 0x65, (byte) 0x0a, (byte) 0x73, (byte) 0x54, (byte) 0x8b, (byte) 0xaf, (byte) 0x63, (byte) 0xde,
        (byte) 0x76, (byte) 0x6a, (byte) 0x0a, (byte) 0xbb, (byte) 0x3c, (byte) 0x77, (byte) 0xb2, (byte) 0xa8,
        (byte) 0x81, (byte) 0xc2, (byte) 0xc9, (byte) 0x2e, (byte) 0x47, (byte) 0xed, (byte) 0xae, (byte) 0xe6,
        (byte) 0x92, (byte) 0x72, (byte) 0x2c, (byte) 0x85, (byte) 0x14, (byte) 0x82, (byte) 0x35, (byte) 0x3b,
        (byte) 0xa2, (byte) 0xbf, (byte) 0xe8, (byte) 0xa1, (byte) 0x4c, (byte) 0xf1, (byte) 0x03, (byte) 0x64,
        (byte) 0xa8, (byte) 0x1a, (byte) 0x66, (byte) 0x4b, (byte) 0xbc, (byte) 0x42, (byte) 0x30, (byte) 0x01,
        (byte) 0xc2, (byte) 0x4b, (byte) 0x8b, (byte) 0x70, (byte) 0xd0, (byte) 0xf8, (byte) 0x97, (byte) 0x91,
        (byte) 0xc7, (byte) 0x6c, (byte) 0x51, (byte) 0xa3, (byte) 0x06, (byte) 0x54, (byte) 0xbe, (byte) 0x30,
        (byte) 0xd1, (byte) 0x92, (byte) 0xe8, (byte) 0x19, (byte) 0xd6, (byte) 0xef, (byte) 0x52, (byte) 0x18,
        (byte) 0xd6, (byte) 0x99, (byte) 0x06, (byte) 0x24, (byte) 0x55, (byte) 0x65, (byte) 0xa9, (byte) 0x10,
        (byte) 0xf4, (byte) 0x0e, (byte) 0x35, (byte) 0x85, (byte) 0x57, (byte) 0x71, (byte) 0x20, (byte) 0x2a,
        (byte) 0x10, (byte) 0x6a, (byte) 0xa0, (byte) 0x70, (byte) 0x32, (byte) 0xbb, (byte) 0xd1, (byte) 0xb8,
        (byte) 0x19, (byte) 0xa4, (byte) 0xc1, (byte) 0x16, (byte) 0xb8, (byte) 0xd2, (byte) 0xd0, (byte) 0xc8,
        (byte) 0x1e, (byte) 0x37, (byte) 0x6c, (byte) 0x08, (byte) 0x51, (byte) 0x41, (byte) 0xab, (byte) 0x53,
        (byte) 0x27, (byte) 0x48, (byte) 0x77, (byte) 0x4c, (byte) 0xdf, (byte) 0x8e, (byte) 0xeb, (byte) 0x99,
        (byte) 0x34, (byte) 0xb0, (byte) 0xbc, (byte) 0xb5, (byte) 0xe1, (byte) 0x9b, (byte) 0x48, (byte) 0xa8,
        (byte) 0x39, (byte) 0x1c, (byte) 0x0c, (byte) 0xb3, (byte) 0xc5, (byte) 0xc9, (byte) 0x5a, (byte) 0x63,
        (byte) 0x4e, (byte) 0xd8, (byte) 0xaa, (byte) 0x4a, (byte) 0xe3, (byte) 0x41, (byte) 0x8a, (byte) 0xcb,
        (byte) 0x5b, (byte) 0x9c, (byte) 0xca, (byte) 0x4f, (byte) 0x77, (byte) 0x63, (byte) 0xe3, (byte) 0x73,
        (byte) 0x68, (byte) 0x2e, (byte) 0x6f, (byte) 0xf3, (byte) 0xd6, (byte) 0xb2, (byte) 0xb8, (byte) 0xa3,
        (byte) 0x74, (byte) 0x8f, (byte) 0x82, (byte) 0xee, (byte) 0x5d, (byte) 0xef, (byte) 0xb2, (byte) 0xfc,
        (byte) 0x78, (byte) 0xa5, (byte) 0x63, (byte) 0x6f, (byte) 0x43, (byte) 0x17, (byte) 0x2f, (byte) 0x60,
        (byte) 0x84, (byte) 0xc8, (byte) 0x78, (byte) 0x14, (byte) 0xa1, (byte) 0xf0, (byte) 0xab, (byte) 0x72,
        (byte) 0x8c, (byte) 0xc7, (byte) 0x02, (byte) 0x08, (byte) 0x1a, (byte) 0x64, (byte) 0x39, (byte) 0xec,
        (byte) 0x90, (byte) 0xbe, (byte) 0xff, (byte) 0xfa, (byte) 0x23, (byte) 0x63, (byte) 0x1e, (byte) 0x28,
        (byte) 0xa4, (byte) 0x50, (byte) 0x6c, (byte) 0xeb, (byte) 0xde, (byte) 0x82, (byte) 0xbd, (byte) 0xe9,
        (byte) 0xbe, (byte) 0xf9, (byte) 0xa3, (byte) 0xf7, (byte) 0xb2, (byte) 0xc6, (byte) 0x79, (byte) 0x15,
        (byte) 0xc6, (byte) 0x71, (byte) 0x78, (byte) 0xf2, (byte) 0xe3, (byte) 0x72, (byte) 0x53, (byte) 0x2b,
        (byte) 0xca, (byte) 0x27, (byte) 0x3e, (byte) 0xce, (byte) 0xea, (byte) 0x26, (byte) 0x61, (byte) 0x9c,
        (byte) 0xd1, (byte) 0x86, (byte) 0xb8, (byte) 0xc7, (byte) 0x21, (byte) 0xc0, (byte) 0xc2, (byte) 0x07,
        (byte) 0xea, (byte) 0xda, (byte) 0x7d, (byte) 0xd6, (byte) 0xcd, (byte) 0xe0, (byte) 0xeb, (byte) 0x1e,
        (byte) 0xf5, (byte) 0x7d, (byte) 0x4f, (byte) 0x7f, (byte) 0xee, (byte) 0x6e, (byte) 0xd1, (byte) 0x78,
        (byte) 0x06, (byte) 0xf0, (byte) 0x67, (byte) 0xaa, (byte) 0x72, (byte) 0x17, (byte) 0x6f, (byte) 0xba,
        (byte) 0x0a, (byte) 0x63, (byte) 0x7d, (byte) 0xc5, (byte) 0xa2, (byte) 0xc8, (byte) 0x98, (byte) 0xa6,
        (byte) 0x11, (byte) 0x3f, (byte) 0x98, (byte) 0x04, (byte) 0xbe, (byte) 0xf9, (byte) 0x0d, (byte) 0xae,
        (byte) 0x1b, (byte) 0x71, (byte) 0x0b, (byte) 0x35, (byte) 0x13, (byte) 0x1c, (byte) 0x47, (byte) 0x1b,
        (byte) 0x28, (byte) 0xdb, (byte) 0x77, (byte) 0xf5, (byte) 0x23, (byte) 0x04, (byte) 0x7d, (byte) 0x84,
        (byte) 0x32, (byte) 0xca, (byte) 0xab, (byte) 0x7b, (byte) 0x40, (byte) 0xc7, (byte) 0x24, (byte) 0x93,
        (byte) 0x3c, (byte) 0x9e, (byte) 0xbe, (byte) 0x0a, (byte) 0x15, (byte) 0xc9, (byte) 0xbe, (byte) 0xbc,
        (byte) 0x43, (byte) 0x1d, (byte) 0x67, (byte) 0xc4, (byte) 0x9c, (byte) 0x10, (byte) 0x0d, (byte) 0x4c,
        (byte) 0x4c, (byte) 0xc5, (byte) 0xd4, (byte) 0xbe, (byte) 0xcb, (byte) 0x3e, (byte) 0x42, (byte) 0xb6,
        (byte) 0x59, (byte) 0x7f, (byte) 0x29, (byte) 0x9c, (byte) 0xfc, (byte) 0x65, (byte) 0x7e, (byte) 0x2a,
        (byte) 0x5f, (byte) 0xcb, (byte) 0x6f, (byte) 0xab, (byte) 0x3a, (byte) 0xd6, (byte) 0xfa, (byte) 0xec,
        (byte) 0x6c, (byte) 0x44, (byte) 0x19, (byte) 0x8c, (byte) 0x4a, (byte) 0x47, (byte) 0x58, (byte) 0x17
    };
    private final byte[] scratch;

    Sha512() {
        this(new byte[SCRATCH_BYTES]);
    }

    /** Card callers supply transient memory; ordinary JVM vectors use the default. */
    Sha512(byte[] suppliedScratch) {
        if (suppliedScratch.length != SCRATCH_BYTES) {
            throw new ArrayIndexOutOfBoundsException();
        }
        scratch = suppliedScratch;
        clear();
    }

    void clear() {
        Wipe.clear(scratch);
    }

    void digest(byte[] input, short offset, short length, byte[] output, short outOffset) {
        boolean complete = false;
        try {
            check(input, offset, length);
            check(output, outOffset, (short) 64);
            short i;
            for (i = 0; i < 64; i++) {
                scratch[i] = INITIAL[i];
            }
            short consumed = 0;
            while ((short) (length - consumed) >= 128) {
                compress(input, (short) (offset + consumed));
                consumed = (short) (consumed + 128);
            }
            short rest = (short) (length - consumed);
            Wipe.clear(scratch, TAIL, (short) 256);
            for (i = 0; i < rest; i++) {
                scratch[(short) (TAIL + i)] = input[(short) (offset + consumed + i)];
            }
            scratch[(short) (TAIL + rest)] = (byte) 0x80;
            short tailLength = rest < 112 ? (short) 128 : (short) 256;
            // The public API is short-bounded, so at most three length bytes are nonzero.
            scratch[(short) (TAIL + tailLength - 3)] = (byte) (length >>> 13);
            scratch[(short) (TAIL + tailLength - 2)] = (byte) (length >>> 5);
            scratch[(short) (TAIL + tailLength - 1)] = (byte) (length << 3);
            compress(scratch, TAIL);
            if (tailLength == 256) {
                compress(scratch, (short) (TAIL + 128));
            }
            for (i = 0; i < 64; i++) {
                output[(short) (outOffset + i)] = scratch[i];
            }
            complete = true;
        } finally {
            clear();
            if (!complete && output != null && outOffset >= 0
                    && outOffset <= (short) (output.length - 64)) {
                Wipe.clear(output, outOffset, (short) 64);
            }
        }
    }

    private static void check(byte[] value, short offset, short length) {
        if (value == null || offset < 0 || length < 0
                || offset > value.length || length > (short) (value.length - offset)) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    private void compress(byte[] block, short offset) {
        short i;
        short j;
        for (i = 0; i < 128; i++) {
            scratch[(short) (W + i)] = block[(short) (offset + i)];
        }
        for (i = 16; i < 80; i++) {
            short word = (short) (W + (short) (i * 8));
            sigma((short) (word - 120), TEMP, (short) 1, (short) 8, (short) 7, true);
            sigma((short) (word - 16), (short) (TEMP + 8), (short) 19,
                    (short) 61, (short) 6, true);
            copy((short) (word - 128), word);
            add(word, scratch, TEMP);
            add(word, scratch, (short) (word - 56));
            add(word, scratch, (short) (TEMP + 8));
        }
        for (i = 0; i < 64; i++) {
            scratch[(short) (V + i)] = scratch[i];
        }
        for (i = 0; i < 80; i++) {
            sigma((short) (V + 32), TEMP, (short) 14, (short) 18,
                    (short) 41, false);
            for (j = 0; j < 8; j++) {
                byte e = scratch[(short) (V + 32 + j)];
                byte f = scratch[(short) (V + 40 + j)];
                byte g = scratch[(short) (V + 48 + j)];
                scratch[(short) (TEMP + 8 + j)] = (byte) ((e & f) ^ (~e & g));
            }
            copy((short) (V + 56), (short) (TEMP + 16));
            add((short) (TEMP + 16), scratch, TEMP);
            add((short) (TEMP + 16), scratch, (short) (TEMP + 8));
            add((short) (TEMP + 16), K, (short) (i * 8));
            add((short) (TEMP + 16), scratch, (short) (W + (short) (i * 8)));
            sigma(V, TEMP, (short) 28, (short) 34, (short) 39, false);
            for (j = 0; j < 8; j++) {
                byte a = scratch[(short) (V + j)];
                byte b = scratch[(short) (V + 8 + j)];
                byte c = scratch[(short) (V + 16 + j)];
                scratch[(short) (TEMP + 8 + j)] = (byte) ((a & b) ^ (a & c) ^ (b & c));
            }
            copy(TEMP, (short) (TEMP + 24));
            add((short) (TEMP + 24), scratch, (short) (TEMP + 8));
            for (j = 7; j > 0; j--) {
                copy((short) (V + (short) ((j - 1) * 8)),
                        (short) (V + (short) (j * 8)));
            }
            add((short) (V + 32), scratch, (short) (TEMP + 16));
            copy((short) (TEMP + 16), V);
            add(V, scratch, (short) (TEMP + 24));
        }
        for (i = 0; i < 8; i++) {
            add((short) (i * 8), scratch, (short) (V + (short) (i * 8)));
        }
    }

    private void copy(short from, short to) {
        short i;
        for (i = 0; i < 8; i++) {
            scratch[(short) (to + i)] = scratch[(short) (from + i)];
        }
    }

    private void add(short destination, byte[] value, short offset) {
        short carry = 0;
        short i;
        for (i = 7; i >= 0; i--) {
            short sum = (short) ((scratch[(short) (destination + i)] & 255)
                    + (value[(short) (offset + i)] & 255) + carry);
            scratch[(short) (destination + i)] = (byte) sum;
            carry = (short) (sum >>> 8);
        }
    }

    private void sigma(short from, short to, short a, short b, short c, boolean shifted) {
        short i;
        for (i = 0; i < 8; i++) {
            byte last = shifted ? shift(from, i, c) : rotate(from, i, c);
            scratch[(short) (to + i)] = (byte) (rotate(from, i, a)
                    ^ rotate(from, i, b) ^ last);
        }
    }

    private byte rotate(short from, short position, short bits) {
        short whole = (short) (bits >>> 3);
        short rest = (short) (bits & 7);
        short index = (short) ((position - whole + 8) & 7);
        short first = (short) (scratch[(short) (from + index)] & 255);
        if (rest == 0) {
            return (byte) first;
        }
        short previous = (short) ((index + 7) & 7);
        short second = (short) (scratch[(short) (from + previous)] & 255);
        return (byte) ((first >>> rest) | (second << (short) (8 - rest)));
    }

    private byte shift(short from, short position, short bits) {
        short whole = (short) (bits >>> 3);
        short rest = (short) (bits & 7);
        short index = (short) (position - whole);
        if (index < 0) {
            return 0;
        }
        short first = (short) (scratch[(short) (from + index)] & 255);
        if (rest == 0 || index == 0) {
            return (byte) (first >>> rest);
        }
        short second = (short) (scratch[(short) (from + index - 1)] & 255);
        return (byte) ((first >>> rest) | (second << (short) (8 - rest)));
    }
}
