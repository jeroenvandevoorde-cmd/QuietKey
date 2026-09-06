package org.quietkey.cardb;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.ISOException;
import javacard.framework.Util;

/** QK-DEC-161 fixed short-APDU grammar. No extended-length interface is used. */
final class Protocol {
    static final byte SELECT = (byte) 0xa4;
    static final byte OPEN = (byte) 0x10;
    static final byte INFO = (byte) 0x11;
    static final byte READ_D = (byte) 0x12;
    static final byte EXPORT_A2 = (byte) 0x13;
    static final byte SIGN = (byte) 0x15;
    static final byte BEGIN = (byte) 0x20;
    static final byte WRITE = (byte) 0x21;
    static final byte COMMIT = (byte) 0x22;
    static final byte ABORT = (byte) 0x23;
    static final short MAX_DATA = (short) 215;
    static final short MAX_REPLY = (short) 216;
    static final short ENVELOPE = (short) 21;
    static final byte SETUP = (byte) 1;
    static final byte NORMAL = (byte) 2;
    static final byte RESTORE = (byte) 3;
    static final byte RESCUE = (byte) 4;
    static final byte UNPROVISIONED = (byte) 0;
    static final byte STAGING = (byte) 1;
    static final byte COMMITTED = (byte) 2;
    static final byte RETIRED = (byte) 0xff;
    private static final byte[] AID = {
        (byte) 0xf0, (byte) 0x51, (byte) 0x4b,
        (byte) 0x32, (byte) 0x42, (byte) 0x01
    };

    private Protocol() { }

    static byte checkHeader(APDU apdu) {
        if (APDU.getProtocol() != APDU.PROTOCOL_T1) {
            ISOException.throwIt((short) 0x6f02);
        }
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[0];
        if (cla != (byte) 0 && cla != (byte) 0x80) {
            ISOException.throwIt((short) 0x6e00);
        }
        byte instruction = buffer[1];
        if (!knownInstruction(instruction)) {
            ISOException.throwIt((short) 0x6d00);
        }
        if ((instruction == SELECT && cla != (byte) 0)
                || (instruction != SELECT && cla != (byte) 0x80)) {
            ISOException.throwIt((short) 0x6e00);
        }
        if (buffer[3] != (byte) 0
                || buffer[2] != (instruction == SELECT ? (byte) 4 : (byte) 0)) {
            ISOException.throwIt((short) 0x6a86);
        }
        return instruction;
    }

    static boolean knownInstruction(byte instruction) {
        switch (instruction) {
        case SELECT:
        case OPEN:
        case INFO:
        case READ_D:
        case EXPORT_A2:
        case SIGN:
        case BEGIN:
        case WRITE:
        case COMMIT:
        case ABORT:
            return true;
        default:
            return false;
        }
    }

    /** Receive only Lc bytes; require the T=1 case-4 Ne=256 before semantics. */
    static short receive(APDU apdu, byte instruction, byte[] data) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) (buffer[4] & (short) 0x00ff);
        checkDataLength(instruction, length);
        short copied = (short) 0;
        try {
            short received = apdu.setIncomingAndReceive();
            if (apdu.getIncomingLength() != length
                    || apdu.getOffsetCdata() != (short) 5) {
                ISOException.throwIt((short) 0x6700);
            }
            while (copied < length) {
                if (received <= (short) 0 || received > (short) (length - copied)) {
                    ISOException.throwIt((short) 0x6700);
                }
                Util.arrayCopyNonAtomic(buffer, (short) 5, data, copied, received);
                copied = (short) (copied + received);
                if (copied < length) {
                    Wipe.clear(buffer);
                    received = apdu.receiveBytes((short) 5);
                }
            }
            // Java Card RE 3.0.5 section 9.4.2: T=1 case 3 gives Ne=0;
            // case 4 with Le=00 gives Ne=256. This check precedes all effects.
            if (apdu.setOutgoing() != (short) 256) {
                ISOException.throwIt((short) 0x6700);
            }
        } catch (APDUException failure) {
            ISOException.throwIt((short) 0x6700);
        }
        return copied;
    }

    static void checkDataLength(byte instruction, short length) {
        boolean accepted;
        switch (instruction) {
        case SELECT: accepted = length == (short) 6; break;
        case OPEN: accepted = length == (short) 18; break;
        case INFO:
        case COMMIT:
        case ABORT: accepted = length == ENVELOPE; break;
        case READ_D: accepted = length == (short) 24; break;
        case EXPORT_A2: accepted = length == (short) 22; break;
        case SIGN: accepted = length == (short) 126; break;
        case BEGIN: accepted = length == (short) 34; break;
        case WRITE: accepted = length == (short) 36 || length == MAX_DATA; break;
        default: accepted = false; break;
        }
        if (!accepted) {
            ISOException.throwIt((short) 0x6700);
        }
    }

    static void checkAid(byte[] data) {
        if (!equal(data, (short) 0, AID, (short) 0, (short) 6)) {
            ISOException.throwIt((short) 0x6f06);
        }
    }

    static void checkVersion(byte[] data) {
        if (data[0] != (byte) 1) {
            ISOException.throwIt((short) 0x6f01);
        }
    }

    static boolean validMode(byte mode) {
        return mode >= SETUP && mode <= RESCUE;
    }

    static boolean equal(byte[] left, short leftOffset, byte[] right,
            short rightOffset, short length) {
        byte difference = (byte) 0;
        for (short i = (short) 0; i < length; i++) {
            difference |= (byte) (left[(short) (leftOffset + i)]
                    ^ right[(short) (rightOffset + i)]);
        }
        return difference == (byte) 0;
    }

    static boolean greaterU32(byte[] left, short leftOffset,
            byte[] right, short rightOffset) {
        for (short i = (short) 0; i < (short) 4; i++) {
            short a = (short) (left[(short) (leftOffset + i)] & (short) 0x00ff);
            short b = (short) (right[(short) (rightOffset + i)] & (short) 0x00ff);
            if (a != b) {
                return a > b;
            }
        }
        return false;
    }

    static short getU16(byte[] data, short offset) {
        return Util.getShort(data, offset);
    }
}
