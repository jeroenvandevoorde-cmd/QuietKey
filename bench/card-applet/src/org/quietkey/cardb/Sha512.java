package org.quietkey.cardb;

import javacard.security.MessageDigest;

/** One nonshared platform digest, reset within every synchronous use. */
final class Sha512 {
    private final MessageDigest digest;

    Sha512() {
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    }

    void digest(byte[] input, short offset, short length, byte[] output, short outOffset) {
        boolean complete = false;
        try {
            check(input, offset, length);
            check(output, outOffset, (short) 64);
            digest.reset();
            if (digest.doFinal(input, offset, length, output, outOffset) != (short) 64) {
                throw new RuntimeException();
            }
            complete = true;
        } finally {
            boolean resetComplete = false;
            try {
                digest.reset();
                resetComplete = true;
            } finally {
                if ((!complete || !resetComplete) && output != null && outOffset >= 0
                        && outOffset <= (short) (output.length - 64)) {
                    Wipe.clear(output, outOffset, (short) 64);
                }
            }
        }
    }

    private static void check(byte[] value, short offset, short length) {
        if (value == null || offset < 0 || length < 0
                || offset > value.length || length > (short) (value.length - offset)) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }
}
