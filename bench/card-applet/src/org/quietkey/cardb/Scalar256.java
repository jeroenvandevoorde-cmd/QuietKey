package org.quietkey.cardb;

/** BIP32 fixed-width scalar checks and one-subtraction addition modulo secp256k1 n. */
final class Scalar256 {
    static final short SCRATCH_BYTES = 33;
    static final byte[] ORDER = {
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
        (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
        (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b,
        (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c,
        (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41
    };
    private final byte[] scratch;

    Scalar256() {
        this(new byte[SCRATCH_BYTES]);
    }

    Scalar256(byte[] suppliedScratch) {
        if (suppliedScratch.length != SCRATCH_BYTES) {
            throw new ArrayIndexOutOfBoundsException();
        }
        scratch = suppliedScratch;
        clear();
    }

    void clear() {
        Wipe.clear(scratch);
    }

    static boolean isValid(byte[] value, short offset) {
        if (!within(value, offset) || !lessThanOrder(value, offset)) {
            return false;
        }
        short i;
        byte nonzero = 0;
        for (i = 0; i < 32; i++) {
            nonzero |= value[(short) (offset + i)];
        }
        return nonzero != 0;
    }

    boolean add(byte[] parent, short parentOffset, byte[] tweak, short tweakOffset,
            byte[] output, short outOffset) {
        boolean accepted = false;
        try {
            if (!within(output, outOffset) || !isValid(parent, parentOffset)
                    || !within(tweak, tweakOffset) || !lessThanOrder(tweak, tweakOffset)) {
                return false;
            }
            short carry = 0;
            short i;
            for (i = 31; i >= 0; i--) {
                short sum = (short) ((parent[(short) (parentOffset + i)] & 255)
                        + (tweak[(short) (tweakOffset + i)] & 255) + carry);
                scratch[(short) (i + 1)] = (byte) sum;
                carry = (short) (sum >>> 8);
            }
            scratch[0] = (byte) carry;
            if (scratch[0] != 0 || !lessThanOrder(scratch, (short) 1)) {
                short borrow = 0;
                for (i = 31; i >= 0; i--) {
                    short difference = (short) ((scratch[(short) (i + 1)] & 255)
                            - (ORDER[i] & 255) - borrow);
                    scratch[(short) (i + 1)] = (byte) difference;
                    borrow = difference < 0 ? (short) 1 : (short) 0;
                }
                scratch[0] = (byte) ((scratch[0] & 255) - borrow);
            }
            byte nonzero = 0;
            for (i = 0; i < 32; i++) {
                output[(short) (outOffset + i)] = scratch[(short) (i + 1)];
                nonzero |= scratch[(short) (i + 1)];
            }
            accepted = nonzero != 0;
            return accepted;
        } finally {
            clear();
            if (!accepted && within(output, outOffset)) {
                Wipe.clear(output, outOffset, (short) 32);
            }
        }
    }

    private static boolean within(byte[] value, short offset) {
        return value != null && offset >= 0 && offset <= (short) (value.length - 32);
    }

    private static boolean lessThanOrder(byte[] value, short offset) {
        short i;
        for (i = 0; i < 32; i++) {
            short left = (short) (value[(short) (offset + i)] & 255);
            short right = (short) (ORDER[i] & 255);
            if (left != right) {
                return left < right;
            }
        }
        return false;
    }
}
