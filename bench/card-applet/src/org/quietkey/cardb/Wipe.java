package org.quietkey.cardb;

import javacard.framework.Util;

/** Explicit clearing for fixed owners; target remanence remains a physical obligation. */
final class Wipe {
    private Wipe() {}

    static void clear(byte[] bytes) {
        clear(bytes, (short) 0, (short) bytes.length);
    }

    static void clear(byte[] bytes, short offset, short length) {
        Util.arrayFillNonAtomic(bytes, offset, length, (byte) 0);
    }
}
