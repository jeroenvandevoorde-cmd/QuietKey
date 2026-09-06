package org.quietkey.cardb;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/** Native-only curve boundary; unavailable primitives fail, with no software fallback. */
final class NativeSecp256k1 {
    private static final byte[] FIELD = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC, (byte) 0x2F
    };
    private static final byte[] A = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    private static final byte[] B = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
    };
    private static final byte[] GENERATOR = {
        (byte) 0x04, (byte) 0x79, (byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9, (byte) 0xDC, (byte) 0xBB,
        (byte) 0xAC, (byte) 0x55, (byte) 0xA0, (byte) 0x62, (byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B,
        (byte) 0x07, (byte) 0x02, (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D, (byte) 0xCE, (byte) 0x28,
        (byte) 0xD9, (byte) 0x59, (byte) 0xF2, (byte) 0x81, (byte) 0x5B, (byte) 0x16, (byte) 0xF8, (byte) 0x17,
        (byte) 0x98, (byte) 0x48, (byte) 0x3A, (byte) 0xDA, (byte) 0x77, (byte) 0x26, (byte) 0xA3, (byte) 0xC4,
        (byte) 0x65, (byte) 0x5D, (byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11, (byte) 0x08,
        (byte) 0xA8, (byte) 0xFD, (byte) 0x17, (byte) 0xB4, (byte) 0x48, (byte) 0xA6, (byte) 0x85, (byte) 0x54,
        (byte) 0x19, (byte) 0x9C, (byte) 0x47, (byte) 0xD0, (byte) 0x8F, (byte) 0xFB, (byte) 0x10, (byte) 0xD4,
        (byte) 0xB8
    };
    private final byte[] point;
    private ECPrivateKey key;
    private KeyAgreement agreement;
    private Signature signer;
    private boolean available;

    NativeSecp256k1() {
        point = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        try {
            key = (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_EC_FP_256, false);
            agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
            signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            available = true;
        } catch (CryptoException unavailable) {
            available = false;
        } finally {
            clear();
        }
    }

    void clear() {
        try {
            if (key != null) {
                key.clearKey();
            }
        } finally {
            Wipe.clear(point);
        }
    }

    private void importScalar(byte[] scalar, short offset) {
        key.setFieldFP(FIELD, (short) 0, (short) 32);
        key.setA(A, (short) 0, (short) 32);
        key.setB(B, (short) 0, (short) 32);
        key.setG(GENERATOR, (short) 0, (short) 65);
        key.setR(Scalar256.ORDER, (short) 0, (short) 32);
        key.setK((short) 1);
        key.setS(scalar, offset, (short) 32);
    }

    boolean publicKey(byte[] scalar, short offset, byte[] output, short outOffset) {
        boolean complete = false;
        try {
            if (!available || !Scalar256.isValid(scalar, offset)
                    || !within(output, outOffset, (short) 33)) {
                return false;
            }
            importScalar(scalar, offset);
            agreement.init(key);
            short length = agreement.generateSecret(GENERATOR, (short) 0, (short) 65,
                    point, (short) 0);
            // The ratified XY primitive returns ANSI X9.62 uncompressed form.
            if (length != 65 || point[0] != 4) {
                return false;
            }
            output[outOffset] = (byte) (2 | (point[64] & 1));
            short i;
            for (i = 0; i < 32; i++) {
                output[(short) (outOffset + 1 + i)] = point[(short) (1 + i)];
            }
            complete = true;
            return true;
        } catch (CryptoException failure) {
            return false;
        } finally {
            boolean cleared = false;
            try {
                clear();
                cleared = true;
            } finally {
                if ((!complete || !cleared) && within(output, outOffset, (short) 33)) {
                    Wipe.clear(output, outOffset, (short) 33);
                }
            }
        }
    }

    short sign(byte[] scalar, short offset, byte[] digest, short digestOffset,
            byte[] output, short outOffset) {
        boolean complete = false;
        try {
            if (!available || !Scalar256.isValid(scalar, offset)
                    || !within(digest, digestOffset, (short) 32)
                    || !within(output, outOffset, (short) 72)) {
                return 0;
            }
            importScalar(scalar, offset);
            signer.init(key, Signature.MODE_SIGN);
            Wipe.clear(output, outOffset, (short) 72);
            // No update() or sign() call: the caller's 32-byte digest is signed directly.
            short length = signer.signPreComputedHash(digest, digestOffset, (short) 32,
                    output, outOffset);
            if (!strictDer(output, outOffset, length)) {
                return 0;
            }
            complete = true;
            return length;
        } catch (CryptoException failure) {
            return 0;
        } finally {
            boolean cleared = false;
            try {
                clear();
                cleared = true;
            } finally {
                if ((!complete || !cleared) && within(output, outOffset, (short) 72)) {
                    Wipe.clear(output, outOffset, (short) 72);
                }
            }
        }
    }

    private static boolean within(byte[] value, short offset, short length) {
        return value != null && offset >= 0 && length >= 0
                && offset <= value.length && length <= (short) (value.length - offset);
    }

    private static boolean strictDer(byte[] value, short offset, short length) {
        if (length < 8 || length > 72 || value[offset] != 0x30
                || (short) (value[(short) (offset + 1)] & 255) != (short) (length - 2)
                || value[(short) (offset + 2)] != 2) {
            return false;
        }
        short rLength = (short) (value[(short) (offset + 3)] & 255);
        short sTag = (short) (offset + 4 + rLength);
        if (rLength < 1 || rLength > 33 || sTag > (short) (offset + length - 3)
                || value[sTag] != 2) {
            return false;
        }
        short sLength = (short) (value[(short) (sTag + 1)] & 255);
        if (sLength < 1 || sLength > 33
                || (short) (sTag + 2 + sLength) != (short) (offset + length)) {
            return false;
        }
        return integer(value, (short) (offset + 4), rLength)
                && integer(value, (short) (sTag + 2), sLength);
    }

    private static boolean integer(byte[] value, short offset, short length) {
        if ((value[offset] & 0x80) != 0) {
            return false;
        }
        if (value[offset] == 0) {
            if (length == 1 || (value[(short) (offset + 1)] & 0x80) == 0) {
                return false;
            }
            offset++;
            length--;
        }
        if (length > 32) {
            return false;
        }
        byte nonzero = 0;
        short i;
        short relation = 0;
        for (i = 0; i < length; i++) {
            short left = (short) (value[(short) (offset + i)] & 255);
            nonzero |= value[(short) (offset + i)];
            if (length == 32 && relation == 0) {
                short right = (short) (Scalar256.ORDER[i] & 255);
                if (left < right) {
                    relation = -1;
                } else if (left > right) {
                    relation = 1;
                }
            }
        }
        return nonzero != 0 && (length < 32 || relation < 0);
    }
}
