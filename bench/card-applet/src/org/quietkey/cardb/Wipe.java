package org.quietkey.cardb;

/** Explicit clearing for fixed owners; target remanence remains a physical obligation. */
final class Wipe {
    private Wipe() {}

    static void clear(byte[] bytes) {
        clear(bytes, (short) 0, (short) bytes.length);
    }

    static void clear(byte[] bytes, short offset, short length) {
        short i;
        for (i = 0; i < length; i++) {
            bytes[(short) (offset + i)] = 0;
        }
    }
}
