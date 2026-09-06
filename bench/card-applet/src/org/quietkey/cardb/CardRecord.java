package org.quietkey.cardb;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

/** Persistent fixed record and transient native-operation ownership. */
final class CardRecord {
    private static final short RECORD_BYTES = (short) 781;
    private static final short INSTANCE = (short) 7;
    private static final short WALLET = (short) 23;
    private static final short FINGERPRINT = (short) 55;
    private static final short XPRV = (short) 59;
    private static final short CHAIN = (short) 72;
    private static final short SCALAR = (short) 105;
    private static final short A2 = (short) 137;
    private static final short RECEIVE = (short) 169;
    private static final short CHANGE = (short) 475;
    private static final byte[] RECORD_DOMAIN = {
        'Q', 'u', 'i', 'e', 't', 'K', 'e', 'y', '/',
        'C', 'a', 'r', 'd', 'R', 'e', 'c', 'o', 'r', 'd', '/', 'v', '1'
    };
    private static final byte[] INSTANCE_DOMAIN = {
        'Q', 'u', 'i', 'e', 't', 'K', 'e', 'y', '/',
        'C', 'a', 'r', 'd', 'I', 'n', 's', 't', 'a', 'n', 'c', 'e', '/', 'v', '1'
    };
    private static final byte[] ZERO = { (byte) 0 };

    private final byte[] committed;
    private final byte[] staged;
    private final byte[] storedXpub;
    private final byte[] storedDigest;
    private final byte[] nonce;
    private byte life;
    private byte provisionMode;
    private byte ordinal;
    private short filled;

    private final MessageDigest sha256;
    private final NativeSecp256k1 nativeCurve;
    private final HmacSha512 hmac;
    private final Scalar256 scalarMath;
    private final byte[] hash;
    private final byte[] xpub;
    private final byte[] childScalar;
    private final byte[] childChain;
    private final byte[] childPublic;
    private final byte[] message;
    private final byte[] material;
    private final byte[] nextScalar;
    private final byte[] ready;

    CardRecord() {
        committed = new byte[RECORD_BYTES];
        staged = new byte[RECORD_BYTES];
        storedXpub = new byte[(short) 78];
        storedDigest = new byte[(short) 32];
        nonce = new byte[(short) 12];
        life = Protocol.UNPROVISIONED;
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        nativeCurve = new NativeSecp256k1();
        Sha512 sha512 = new Sha512(transientBytes(Sha512.SCRATCH_BYTES));
        hmac = new HmacSha512(sha512, transientBytes(HmacSha512.SCRATCH_BYTES));
        scalarMath = new Scalar256(transientBytes(Scalar256.SCRATCH_BYTES));
        hash = transientBytes((short) 32);
        xpub = transientBytes((short) 78);
        childScalar = transientBytes((short) 32);
        childChain = transientBytes((short) 32);
        childPublic = transientBytes((short) 33);
        message = transientBytes((short) 37);
        material = transientBytes((short) 64);
        nextScalar = transientBytes((short) 32);
        ready = transientBytes((short) 1);
    }

    private static byte[] transientBytes(short length) {
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
    }

    byte lifecycle() {
        return life;
    }

    byte stagingMode() {
        return provisionMode;
    }

    boolean stagingComplete() {
        return life == Protocol.STAGING && filled == RECORD_BYTES;
    }

    void clearTransient() {
        try {
            nativeCurve.clear();
        } finally {
            hmac.clear();
            scalarMath.clear();
            Wipe.clear(hash);
            Wipe.clear(xpub);
            Wipe.clear(childScalar);
            Wipe.clear(childChain);
            Wipe.clear(childPublic);
            Wipe.clear(message);
            Wipe.clear(material);
            Wipe.clear(nextScalar);
            Wipe.clear(ready);
            sha256.reset();
        }
    }

    void checkOpen(byte mode) {
        if (life == Protocol.UNPROVISIONED) {
            if (mode != Protocol.SETUP && mode != Protocol.RESTORE) {
                ISOException.throwIt((short) 0x6f07);
            }
        } else if (life == Protocol.STAGING) {
            if (mode != provisionMode) {
                ISOException.throwIt((short) 0x6f07);
            }
        } else if (life == Protocol.COMMITTED) {
            boolean matches = false;
            try {
                recordDigest(committed, hash);
                matches = Protocol.equal(hash, (short) 0, storedDigest, (short) 0, (short) 32);
            } catch (CryptoException failure) {
                integrityFailure();
            } finally {
                clearTransient();
            }
            if (!matches) {
                integrityFailure();
            }
        } else if (life != Protocol.RETIRED) {
            integrityFailure();
        }
    }

    short info(byte mode, byte[] output, short offset) {
        Wipe.clear(output, offset, (short) 137);
        output[offset] = (byte) 1;
        output[(short) (offset + 1)] = (byte) 1;
        output[(short) (offset + 2)] = life;
        output[(short) (offset + 4)] = (byte) 2;
        if (life == Protocol.COMMITTED) {
            output[(short) (offset + 3)] = committed[5];
            Util.arrayCopyNonAtomic(committed, INSTANCE, output,
                    (short) (offset + 5), (short) 16);
            Util.arrayCopyNonAtomic(committed, WALLET, output,
                    (short) (offset + 21), (short) 32);
            Util.arrayCopyNonAtomic(committed, FINGERPRINT, output,
                    (short) (offset + 53), (short) 4);
            Util.arrayCopyNonAtomic(storedXpub, (short) 0, output,
                    (short) (offset + 57), (short) 78);
        }
        Util.setShort(output, (short) (offset + 135), allowedMask(mode));
        return (short) 137;
    }

    private short allowedMask(byte mode) {
        if (life == Protocol.UNPROVISIONED) {
            return (short) 0x0011;
        }
        if (life == Protocol.STAGING) {
            return filled == RECORD_BYTES ? (short) 0x00d1 : (short) 0x00b1;
        }
        if (life == Protocol.COMMITTED) {
            if (mode == Protocol.SETUP) {
                return (short) 0x0007;
            }
            if (mode == Protocol.RESTORE) {
                return (short) 0x0003;
            }
            return (short) 0x000f;
        }
        return (short) 0x0001;
    }

    void begin(byte mode, byte requestedOrdinal, byte[] input, short nonceOffset) {
        requireProvisioningMode(mode);
        if (life != Protocol.UNPROVISIONED && life != Protocol.STAGING) {
            ISOException.throwIt((short) 0x6f07);
        }
        if ((mode == Protocol.SETUP && requestedOrdinal != (byte) 1
                    && requestedOrdinal != (byte) 2)
                || (mode == Protocol.RESTORE && requestedOrdinal != (byte) 3)) {
            ISOException.throwIt((short) 0x6f08);
        }
        try {
            JCSystem.beginTransaction();
            clearStaging();
            Util.arrayCopy(input, nonceOffset, nonce, (short) 0, (short) 12);
            ordinal = requestedOrdinal;
            provisionMode = mode;
            life = Protocol.STAGING;
            JCSystem.commitTransaction();
        } catch (RuntimeException failure) {
            integrityFailure();
        }
    }

    short write(byte mode, short offset, byte[] input, short dataOffset, short length) {
        requireProvisioningMode(mode);
        if (life != Protocol.STAGING) {
            ISOException.throwIt((short) 0x6f07);
        }
        short expectedLength = filled == (short) 768 ? (short) 13 : (short) 192;
        if (filled >= RECORD_BYTES || offset != filled || length != expectedLength) {
            ISOException.throwIt((short) 0x6f08);
        }
        short next = (short) (filled + length);
        try {
            JCSystem.beginTransaction();
            Util.arrayCopy(input, dataOffset, staged, filled, length);
            filled = next;
            JCSystem.commitTransaction();
        } catch (RuntimeException failure) {
            integrityFailure();
        }
        return next;
    }

    void abort(byte mode) {
        requireProvisioningMode(mode);
        if (life != Protocol.STAGING) {
            ISOException.throwIt((short) 0x6f07);
        }
        try {
            JCSystem.beginTransaction();
            clearStaging();
            life = Protocol.UNPROVISIONED;
            JCSystem.commitTransaction();
        } catch (RuntimeException failure) {
            integrityFailure();
        }
    }

    void commit(byte mode) {
        requireProvisioningMode(mode);
        if (life != Protocol.STAGING) {
            ISOException.throwIt((short) 0x6f07);
        }
        if (filled != RECORD_BYTES) {
            ISOException.throwIt((short) 0x6f08);
        }
        try {
            validateRecord();
            recordDigest(staged, hash);
            try {
                JCSystem.beginTransaction();
                Util.arrayCopy(staged, (short) 0, committed, (short) 0, RECORD_BYTES);
                Util.arrayCopy(xpub, (short) 0, storedXpub, (short) 0, (short) 78);
                Util.arrayCopy(hash, (short) 0, storedDigest, (short) 0, (short) 32);
                clearStaging();
                life = Protocol.COMMITTED;
                JCSystem.commitTransaction();
            } catch (RuntimeException failure) {
                integrityFailure();
            }
        } catch (CryptoException failure) {
            ISOException.throwIt((short) 0x6f0e);
        } finally {
            clearTransient();
        }
    }

    private void validateRecord() {
        if (staged[0] != 'Q' || staged[1] != 'K' || staged[2] != 'C' || staged[3] != 'B'
                || staged[4] != (byte) 1 || staged[5] < (byte) 1 || staged[5] > (byte) 3
                || staged[6] != (byte) 2
                || staged[XPRV] != (byte) 0x04 || staged[(short) (XPRV + 1)] != (byte) 0x88
                || staged[(short) (XPRV + 2)] != (byte) 0xad
                || staged[(short) (XPRV + 3)] != (byte) 0xe4
                || staged[(short) (XPRV + 4)] != (byte) 4
                || staged[(short) (XPRV + 9)] != (byte) 0x80
                || staged[(short) (XPRV + 10)] != (byte) 0
                || staged[(short) (XPRV + 11)] != (byte) 0
                || staged[(short) (XPRV + 12)] != (byte) 2
                || staged[(short) (XPRV + 45)] != (byte) 0
                || !Scalar256.isValid(staged, SCALAR)) {
            ISOException.throwIt((short) 0x6f09);
        }
        sha256.reset();
        sha256.update(staged, RECEIVE, (short) 306);
        sha256.update(ZERO, (short) 0, (short) 1);
        sha256.doFinal(staged, CHANGE, (short) 306, hash, (short) 0);
        if (!Protocol.equal(hash, (short) 0, staged, WALLET, (short) 32)) {
            ISOException.throwIt((short) 0x6f0a);
        }
        sha256.reset();
        sha256.update(INSTANCE_DOMAIN, (short) 0, (short) INSTANCE_DOMAIN.length);
        sha256.update(ZERO, (short) 0, (short) 1);
        sha256.update(staged, WALLET, (short) 32);
        sha256.update(ZERO, (short) 0, (short) 1);
        message[0] = ordinal;
        sha256.update(message, (short) 0, (short) 1);
        sha256.doFinal(nonce, (short) 0, (short) 12, hash, (short) 0);
        if (!Protocol.equal(hash, (short) 0, staged, INSTANCE, (short) 16)) {
            ISOException.throwIt((short) 0x6f0a);
        }
        Wipe.clear(xpub);
        xpub[0] = (byte) 0x04;
        xpub[1] = (byte) 0x88;
        xpub[2] = (byte) 0xb2;
        xpub[3] = (byte) 0x1e;
        Util.arrayCopyNonAtomic(staged, (short) (XPRV + 4), xpub, (short) 4, (short) 41);
        if (!nativeCurve.publicKey(staged, SCALAR, xpub, (short) 45)) {
            ISOException.throwIt((short) 0x6f0e);
        }
    }

    private void recordDigest(byte[] record, byte[] output) {
        sha256.reset();
        sha256.update(RECORD_DOMAIN, (short) 0, (short) RECORD_DOMAIN.length);
        sha256.update(ZERO, (short) 0, (short) 1);
        sha256.doFinal(record, (short) 0, RECORD_BYTES, output, (short) 0);
    }

    short read(byte selector, short offset, byte[] output, short outOffset) {
        if ((selector != (byte) 1 && selector != (byte) 2)
                || (offset != (short) 0 && offset != (short) 192)) {
            ISOException.throwIt((short) 0x6f06);
        }
        requireCommitted();
        short source = selector == (byte) 1 ? RECEIVE : CHANGE;
        short length = offset == (short) 0 ? (short) 192 : (short) 114;
        Util.arrayCopyNonAtomic(committed, (short) (source + offset), output, outOffset, length);
        return length;
    }

    void exportA2(byte[] output, short offset) {
        requireCommitted();
        Util.arrayCopyNonAtomic(committed, A2, output, offset, (short) 32);
    }

    boolean walletMatches(byte[] input, short offset) {
        requireCommitted();
        return Protocol.equal(input, offset, committed, WALLET, (short) 32);
    }

    void prepareChild(byte branch, byte[] input, short indexOffset) {
        clearTransient();
        requireCommitted();
        if ((branch != (byte) 0 && branch != (byte) 1)
                || input[indexOffset] != (byte) 0
                || input[(short) (indexOffset + 1)] != (byte) 0) {
            ISOException.throwIt((short) 0x6f0b);
        }
        boolean complete = false;
        try {
            Util.arrayCopyNonAtomic(committed, SCALAR, childScalar, (short) 0, (short) 32);
            Util.arrayCopyNonAtomic(committed, CHAIN, childChain, (short) 0, (short) 32);
            Wipe.clear(message);
            message[36] = branch;
            deriveChild();
            Wipe.clear(message);
            Util.arrayCopyNonAtomic(input, indexOffset, message, (short) 33, (short) 4);
            deriveChild();
            if (!nativeCurve.publicKey(childScalar, (short) 0, childPublic, (short) 0)) {
                ISOException.throwIt((short) 0x6f0e);
            }
            ready[0] = (byte) 1;
            complete = true;
        } finally {
            Wipe.clear(message);
            Wipe.clear(material);
            Wipe.clear(nextScalar);
            hmac.clear();
            scalarMath.clear();
            if (!complete) {
                clearTransient();
            }
        }
    }

    private void deriveChild() {
        if (!nativeCurve.publicKey(childScalar, (short) 0, message, (short) 0)) {
            ISOException.throwIt((short) 0x6f0e);
        }
        hmac.compute(childChain, (short) 0, (short) 32, message, (short) 0,
                (short) 37, material, (short) 0);
        if (!scalarMath.add(childScalar, (short) 0, material, (short) 0,
                nextScalar, (short) 0)) {
            ISOException.throwIt((short) 0x6f0c);
        }
        Util.arrayCopyNonAtomic(nextScalar, (short) 0, childScalar, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(material, (short) 32, childChain, (short) 0, (short) 32);
        Wipe.clear(material);
        Wipe.clear(nextScalar);
    }

    short signPrepared(byte[] input, short digestOffset, byte[] output,
            short publicOffset, short derOffset) {
        try {
            requireCommitted();
            if (ready[0] != (byte) 1) {
                ISOException.throwIt((short) 0x6f0e);
            }
            short length = nativeCurve.sign(childScalar, (short) 0,
                    input, digestOffset, output, derOffset);
            if (length < (short) 8 || length > (short) 72) {
                ISOException.throwIt((short) 0x6f0e);
            }
            Util.arrayCopyNonAtomic(childPublic, (short) 0, output, publicOffset, (short) 33);
            return length;
        } finally {
            clearTransient();
        }
    }

    private void requireCommitted() {
        if (life != Protocol.COMMITTED) {
            ISOException.throwIt((short) 0x6f07);
        }
    }

    private void requireProvisioningMode(byte mode) {
        if (life == Protocol.RETIRED) {
            ISOException.throwIt((short) 0x6f07);
        }
        if (mode != Protocol.SETUP && mode != Protocol.RESTORE) {
            ISOException.throwIt((short) 0x6f06);
        }
    }

    /** Transactional during provision/abort/commit; inaccessible after retirement. */
    private void clearStaging() {
        Wipe.clear(staged);
        Wipe.clear(nonce);
        filled = (short) 0;
        ordinal = (byte) 0;
        provisionMode = (byte) 0;
    }

    /** No command enters this absorbing state; every persistent fault is 6F0F. */
    private void integrityFailure() {
        try {
            if (JCSystem.getTransactionDepth() != (byte) 0) {
                JCSystem.abortTransaction();
            }
            // Persist the absorbing state before clearing inaccessible owners.
            // Failure to persist even this one-field transaction is still a
            // persistent fault, never a cryptographic-operation rejection. The
            // status reports failure, not successful physical fault survival.
            JCSystem.beginTransaction();
            life = Protocol.RETIRED;
            JCSystem.commitTransaction();
            Wipe.clear(committed);
            Wipe.clear(storedXpub);
            Wipe.clear(storedDigest);
            clearStaging();
        } finally {
            try {
                if (JCSystem.getTransactionDepth() != (byte) 0) {
                    JCSystem.abortTransaction();
                }
            } finally {
                ISOException.throwIt((short) 0x6f0f);
            }
        }
    }
}
