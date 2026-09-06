package org.quietkey.cardb;

/** Fixed-memory HMAC for the registered 32-byte key, 37-byte CKDpriv message. */
final class HmacSha512 {
    static final short SCRATCH_BYTES = 384;
    private final Sha512 sha;
    private final byte[] scratch;

    HmacSha512() {
        this(new Sha512(), new byte[SCRATCH_BYTES]);
    }

    /** Card callers provide separately owned transient hash and HMAC scratch. */
    HmacSha512(Sha512 suppliedSha, byte[] suppliedScratch) {
        if (suppliedScratch.length != SCRATCH_BYTES) {
            throw new ArrayIndexOutOfBoundsException();
        }
        sha = suppliedSha;
        scratch = suppliedScratch;
        clear();
    }

    void clear() {
        Wipe.clear(scratch);
        sha.clear();
    }

    void compute(byte[] key, short keyOffset, short keyLength,
            byte[] data, short dataOffset, short dataLength, byte[] output, short outOffset) {
        boolean complete = false;
        try {
            if (keyLength < 0 || keyLength > 128 || dataLength < 0 || dataLength > 64
                    || keyOffset < 0 || dataOffset < 0 || outOffset < 0
                    || keyLength > (short) (key.length - keyOffset)
                    || dataLength > (short) (data.length - dataOffset)
                    || outOffset > (short) (output.length - 64)) {
                throw new ArrayIndexOutOfBoundsException();
            }
            short i;
            Wipe.clear(scratch);
            for (i = 0; i < keyLength; i++) {
                scratch[i] = key[(short) (keyOffset + i)];
            }
            for (i = 0; i < 128; i++) {
                scratch[(short) (128 + i)] = (byte) (scratch[i] ^ 0x36);
            }
            for (i = 0; i < dataLength; i++) {
                scratch[(short) (256 + i)] = data[(short) (dataOffset + i)];
            }
            sha.digest(scratch, (short) 128, (short) (128 + dataLength), scratch, (short) 320);
            for (i = 0; i < 128; i++) {
                scratch[(short) (128 + i)] = (byte) (scratch[i] ^ 0x5c);
            }
            for (i = 0; i < 64; i++) {
                scratch[(short) (256 + i)] = scratch[(short) (320 + i)];
            }
            sha.digest(scratch, (short) 128, (short) 192, output, outOffset);
            complete = true;
        } finally {
            clear();
            if (!complete && output != null && outOffset >= 0
                    && outOffset <= (short) (output.length - 64)) {
                Wipe.clear(output, outOffset, (short) 64);
            }
        }
    }
}
