package org.quietkey.cardb;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** One selection's bounded, transient ordering and identity owner. */
final class Session {
    private static final short SELECTED = (short) 0;
    private static final short ACTIVE = (short) 1;
    private static final short MODE = (short) 2;
    private static final short COMMANDS = (short) 3;
    private static final short READ_STEP = (short) 4;
    private static final short A2_USED = (short) 5;
    private static final short SIGN_COUNT = (short) 6;
    private static final short SIGN_BOUND = (short) 7;
    private static final short ID = (short) 0;
    private static final short WALLET = (short) 16;
    private static final short REVIEW = (short) 48;
    private static final short LAST_INPUT = (short) 80;

    private final byte[] state;
    private final byte[] binding;

    Session() {
        state = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        binding = JCSystem.makeTransientByteArray((short) 84, JCSystem.CLEAR_ON_DESELECT);
    }

    void select() {
        clear();
        state[SELECTED] = (byte) 1;
    }

    void clear() {
        Wipe.clear(state);
        Wipe.clear(binding);
    }

    byte mode() {
        return state[MODE];
    }

    short execute(byte instruction, byte[] input, short length,
            byte[] output, CardRecord record) {
        if (instruction == Protocol.SELECT) {
            Protocol.checkAid(input);
            select();
            return (short) 0;
        }
        Protocol.checkVersion(input);
        if (instruction == Protocol.OPEN) {
            return open(input, output, record);
        }
        checkEnvelope(input);
        Util.arrayCopyNonAtomic(input, (short) 0, output, (short) 0, Protocol.ENVELOPE);
        state[COMMANDS] = (byte) ((short) (state[COMMANDS] & (short) 0x00ff) + (short) 1);

        // With each request <=221 and reply <=218, 128 exchanges consume
        // <=56,192 serialized bytes, strictly below the 65,536-byte cap.
        if (instruction != Protocol.INFO && record.lifecycle() == Protocol.RETIRED) {
            ISOException.throwIt((short) 0x6f07);
        }
        switch (instruction) {
        case Protocol.INFO:
            return (short) (Protocol.ENVELOPE + record.info(mode(), output, Protocol.ENVELOPE));
        case Protocol.READ_D:
            return readDescriptor(input, output, record);
        case Protocol.EXPORT_A2:
            return exportA2(input, output, record);
        case Protocol.SIGN:
            return sign(input, output, record);
        case Protocol.BEGIN:
            requireProvisioningMode();
            record.begin(mode(), input[21], input, (short) 22);
            return Protocol.ENVELOPE;
        case Protocol.WRITE:
            requireProvisioningMode();
            short next = record.write(mode(), Protocol.getU16(input, (short) 21),
                    input, (short) 23, (short) (length - (short) 23));
            Util.setShort(output, Protocol.ENVELOPE, next);
            return (short) 23;
        case Protocol.COMMIT:
            requireProvisioningMode();
            record.commit(mode());
            clear();
            return Protocol.ENVELOPE;
        case Protocol.ABORT:
            requireProvisioningMode();
            record.abort(mode());
            clear();
            return Protocol.ENVELOPE;
        default:
            ISOException.throwIt((short) 0x6d00);
            return (short) 0;
        }
    }

    private short open(byte[] input, byte[] output, CardRecord record) {
        if (state[SELECTED] != (byte) 1 || state[ACTIVE] != (byte) 0) {
            ISOException.throwIt((short) 0x6f03);
        }
        byte requestedMode = input[1];
        if (!Protocol.validMode(requestedMode)) {
            ISOException.throwIt((short) 0x6f06);
        }
        record.checkOpen(requestedMode);
        Util.arrayCopyNonAtomic(input, (short) 2, binding, ID, (short) 16);
        state[MODE] = requestedMode;
        state[COMMANDS] = (byte) 1;
        state[ACTIVE] = (byte) 1;
        output[0] = (byte) 1;
        Util.arrayCopyNonAtomic(binding, ID, output, (short) 1, (short) 16);
        // Output is cleared before execute, including all four sequence bytes.
        return Protocol.ENVELOPE;
    }

    private void checkEnvelope(byte[] input) {
        short commands = (short) (state[COMMANDS] & (short) 0x00ff);
        if (state[SELECTED] != (byte) 1 || state[ACTIVE] != (byte) 1
                || commands >= (short) 128) {
            ISOException.throwIt((short) 0x6f03);
        }
        if (!Protocol.equal(input, (short) 1, binding, ID, (short) 16)) {
            ISOException.throwIt((short) 0x6f04);
        }
        // At most 127 post-OPEN requests: this exactly represents the u32BE
        // sequence domain without introducing Java Card optional int arithmetic.
        if (input[17] != (byte) 0 || input[18] != (byte) 0 || input[19] != (byte) 0
                || (short) (input[20] & (short) 0x00ff) != commands) {
            ISOException.throwIt((short) 0x6f05);
        }
    }

    private void requireProvisioningMode() {
        if (mode() != Protocol.SETUP && mode() != Protocol.RESTORE) {
            ISOException.throwIt((short) 0x6f06);
        }
    }

    private short readDescriptor(byte[] input, byte[] output, CardRecord record) {
        byte step = state[READ_STEP];
        byte selector = input[21];
        short offset = Protocol.getU16(input, (short) 22);
        byte expectedSelector = step < (byte) 2 ? (byte) 1 : (byte) 2;
        short expectedOffset = (step == (byte) 0 || step == (byte) 2)
                ? (short) 0 : (short) 192;
        if (step >= (byte) 4 || selector != expectedSelector || offset != expectedOffset) {
            ISOException.throwIt((short) 0x6f06);
        }
        if (record.lifecycle() != Protocol.COMMITTED) {
            ISOException.throwIt((short) 0x6f07);
        }
        output[21] = selector;
        Util.setShort(output, (short) 22, offset);
        short copied = record.read(selector, offset, output, (short) 24);
        state[READ_STEP] = (byte) (step + (byte) 1);
        return (short) ((short) 24 + copied);
    }

    private short exportA2(byte[] input, byte[] output, CardRecord record) {
        byte expected = (byte) 0;
        if (mode() == Protocol.SETUP) {
            expected = (byte) 1;
        } else if (mode() == Protocol.NORMAL) {
            expected = (byte) 2;
        } else if (mode() == Protocol.RESCUE) {
            expected = (byte) 3;
        }
        if (expected == (byte) 0 || input[21] != expected || state[A2_USED] != (byte) 0) {
            ISOException.throwIt((short) 0x6f06);
        }
        if (record.lifecycle() != Protocol.COMMITTED) {
            ISOException.throwIt((short) 0x6f07);
        }
        output[21] = expected;
        record.exportA2(output, (short) 22);
        state[A2_USED] = (byte) 1;
        return (short) 54;
    }

    private short sign(byte[] input, byte[] output, CardRecord record) {
        if ((mode() != Protocol.NORMAL && mode() != Protocol.RESCUE)
                || (short) (state[SIGN_COUNT] & (short) 0x00ff) >= (short) 100) {
            ISOException.throwIt((short) 0x6f06);
        }
        if (record.lifecycle() != Protocol.COMMITTED) {
            ISOException.throwIt((short) 0x6f07);
        }
        if (!record.walletMatches(input, (short) 21)) {
            ISOException.throwIt((short) 0x6f0a);
        }
        if ((input[89] != (byte) 0 && input[89] != (byte) 1)
                || input[90] != (byte) 0 || input[91] != (byte) 0) {
            ISOException.throwIt((short) 0x6f0b);
        }
        short deferredNativeFailure = (short) 0;
        try {
            record.prepareChild(input[89], input, (short) 90);
        } catch (ISOException failure) {
            if (failure.getReason() != (short) 0x6f0e) {
                throw failure;
            }
            deferredNativeFailure = (short) 0x6f0e;
        }
        if (state[SIGN_BOUND] != (byte) 0
                && (!Protocol.equal(input, (short) 21, binding, WALLET, (short) 32)
                    || !Protocol.equal(input, (short) 53, binding, REVIEW, (short) 32)
                    || !Protocol.greaterU32(input, (short) 85, binding, LAST_INPUT))) {
            ISOException.throwIt((short) 0x6f0d);
        }
        if (deferredNativeFailure != (short) 0) {
            ISOException.throwIt(deferredNativeFailure);
        }
        // No native signing takes place before the complete binding checks.
        short derLength = record.signPrepared(input, (short) 94, output,
                (short) 57, (short) 91);
        if (derLength < (short) 8 || derLength > (short) 72) {
            ISOException.throwIt((short) 0x6f0e);
        }
        Util.arrayCopyNonAtomic(input, (short) 53, output, (short) 21, (short) 36);
        output[90] = (byte) derLength;
        if (state[SIGN_BOUND] == (byte) 0) {
            Util.arrayCopyNonAtomic(input, (short) 21, binding, WALLET, (short) 64);
            state[SIGN_BOUND] = (byte) 1;
        }
        Util.arrayCopyNonAtomic(input, (short) 85, binding, LAST_INPUT, (short) 4);
        state[SIGN_COUNT] = (byte) (state[SIGN_COUNT] + (byte) 1);
        return (short) ((short) 91 + derLength);
    }
}
