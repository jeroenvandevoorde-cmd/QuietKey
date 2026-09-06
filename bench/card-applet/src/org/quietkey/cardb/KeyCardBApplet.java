package org.quietkey.cardb;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/** Test-AID applet source; compilation makes no delivered-card capability claim. */
public final class KeyCardBApplet extends Applet {
    private static final byte[] APPLET_AID = {
        (byte) 0xf0, (byte) 0x51, (byte) 0x4b,
        (byte) 0x32, (byte) 0x42, (byte) 0x01
    };

    private final CardRecord record;
    private final Session session;
    private final byte[] input;
    private final byte[] output;

    private KeyCardBApplet() {
        record = new CardRecord();
        session = new Session();
        input = JCSystem.makeTransientByteArray(Protocol.MAX_DATA, JCSystem.CLEAR_ON_DESELECT);
        output = JCSystem.makeTransientByteArray(Protocol.MAX_REPLY, JCSystem.CLEAR_ON_DESELECT);
        register(APPLET_AID, (short) 0, (byte) 6);
    }

    public static void install(byte[] parameters, short offset, byte length) {
        new KeyCardBApplet();
    }

    public boolean select() {
        clearVolatile();
        return true;
    }

    public void deselect() {
        clearVolatile();
    }

    private void clearVolatile() {
        session.clear();
        record.clearTransient();
        Wipe.clear(input);
        Wipe.clear(output);
    }

    public void process(APDU apdu) {
        byte[] runtimeBuffer = apdu.getBuffer();
        Wipe.clear(input);
        Wipe.clear(output);
        try {
            byte instruction = Protocol.checkHeader(apdu);
            short length = Protocol.receive(apdu, instruction, input);
            short replyLength = session.execute(instruction, input, length, output, record);
            // Remove request and derived-key scratch before exposing a reply.
            Wipe.clear(input);
            record.clearTransient();
            apdu.setOutgoingLength(replyLength);
            if (replyLength != (short) 0) {
                apdu.sendBytesLong(output, (short) 0, replyLength);
            }
            // JCRE owns runtimeBuffer and may transmit its final bytes only
            // after return. Do not modify it after the final send; JCRE clears
            // it before the next command. The applet's source owner is cleared.
        } catch (ISOException rejection) {
            clearVolatile();
            Wipe.clear(runtimeBuffer);
            throw rejection;
        } catch (RuntimeException failure) {
            clearVolatile();
            Wipe.clear(runtimeBuffer);
            ISOException.throwIt((short) 0x6f0e);
        } finally {
            Wipe.clear(input);
            Wipe.clear(output);
            record.clearTransient();
        }
    }
}
