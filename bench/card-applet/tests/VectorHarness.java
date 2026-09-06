package org.quietkey.cardb;

// PERMANENTLY NEVER-FUND TEST MATERIAL. No applet runtime or native curve execution.
// Public deterministic arithmetic inputs only; generated values are never printed.
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Ordinary JVM reference ties for pure helpers; not a card or Java Card simulator. */
public final class VectorHarness {
    private static final String ABC_SHA512 =
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    private static final String BIP32_HMAC =
            "a48f35a949087f399e834b02cd9cf0889d13d516eca4b8ed2277376658a0d04c"
            + "bbe3fc64c34f1da7bad6f11e784795f5f91d85da8ea6d73a0e70df290ebbdeec";
    private static int assertions;

    private VectorHarness() {}

    private static void check(boolean accepted, String name) {
        if (!accepted) {
            throw new AssertionError(name);
        }
        assertions++;
    }

    private static void equal(byte[] actual, byte[] expected, String name) {
        check(Arrays.equals(actual, expected), name);
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static byte[] scalar(BigInteger value) {
        byte[] encoded = value.toByteArray();
        byte[] result = new byte[32];
        int count = Math.min(32, encoded.length);
        System.arraycopy(encoded, encoded.length - count, result, 32 - count, count);
        return result;
    }

    private static void knownAnswers() throws Exception {
        Sha512 sha = new Sha512();
        byte[] output = new byte[64];
        sha.digest(new byte[] {97, 98, 99}, (short) 0, (short) 3, output, (short) 0);
        equal(output, hex(ABC_SHA512), "Sha512RegisteredAbc");
        byte[] key = new byte[32];
        byte[] message = new byte[37];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) i;
        }
        new HmacSha512().compute(key, (short) 0, (short) 32,
                message, (short) 0, (short) 37, output, (short) 0);
        equal(output, hex(BIP32_HMAC), "HmacRegisteredCkdShape");
        BigInteger order = new BigInteger(1, Scalar256.ORDER);
        check(!Scalar256.isValid(new byte[32], (short) 0), "ScalarZeroRejected");
        check(!Scalar256.isValid(Scalar256.ORDER, (short) 0), "ScalarOrderRejected");
        check(Scalar256.isValid(scalar(order.subtract(BigInteger.ONE)), (short) 0),
                "ScalarOrderMinusOneAccepted");
    }

    private static void shaTies(Random random) throws Exception {
        Sha512 sha = new Sha512();
        for (int length = 0; length <= 1000; length++) {
            byte[] message = new byte[length];
            random.nextBytes(message);
            byte[] actual = new byte[64];
            sha.digest(message, (short) 0, (short) length, actual, (short) 0);
            equal(actual, MessageDigest.getInstance("SHA-512").digest(message), "Sha512JvmTie");
        }
        byte[] maximum = new byte[32767];
        random.nextBytes(maximum);
        byte[] actual = new byte[64];
        sha.digest(maximum, (short) 0, (short) maximum.length, actual, (short) 0);
        equal(actual, MessageDigest.getInstance("SHA-512").digest(maximum), "Sha512MaximumTie");
        byte[] padded = new byte[200];
        random.nextBytes(padded);
        byte[] expected = MessageDigest.getInstance("SHA-512").digest(Arrays.copyOfRange(padded, 7, 136));
        byte[] result = new byte[80];
        Arrays.fill(result, (byte) 0x55);
        sha.digest(padded, (short) 7, (short) 129, result, (short) 8);
        equal(Arrays.copyOfRange(result, 8, 72), expected, "Sha512OffsetTie");
        equal(Arrays.copyOfRange(result, 0, 8), filled(8, (byte) 0x55), "Sha512PrefixPreserved");
        equal(Arrays.copyOfRange(result, 72, 80), filled(8, (byte) 0x55), "Sha512SuffixPreserved");
        sha.digest(padded, (short) 7, (short) 129, padded, (short) 0);
        equal(Arrays.copyOfRange(padded, 0, 64), expected, "Sha512InputOutputAlias");
    }

    private static void hmacTies(Random random) throws Exception {
        HmacSha512 hmac = new HmacSha512();
        for (int length = 0; length <= 64; length++) {
            for (int keyLength = 1; keyLength <= 128; keyLength += 7) {
                byte[] key = new byte[keyLength];
                byte[] data = new byte[length];
                random.nextBytes(key);
                random.nextBytes(data);
                byte[] actual = new byte[64];
                hmac.compute(key, (short) 0, (short) keyLength,
                        data, (short) 0, (short) length, actual, (short) 0);
                Mac reference = Mac.getInstance("HmacSHA512");
                reference.init(new SecretKeySpec(key, "HmacSHA512"));
                equal(actual, reference.doFinal(data), "HmacJvmTie");
            }
        }
        byte[] key = new byte[128];
        byte[] data = new byte[64];
        random.nextBytes(key);
        random.nextBytes(data);
        Mac reference = Mac.getInstance("HmacSHA512");
        reference.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] expected = reference.doFinal(data);
        hmac.compute(key, (short) 0, (short) 128, data, (short) 0, (short) 64,
                key, (short) 0);
        equal(Arrays.copyOfRange(key, 0, 64), expected, "HmacKeyOutputAlias");
    }

    private static void scalarTies(Random random) {
        BigInteger order = new BigInteger(1, Scalar256.ORDER);
        Scalar256 addition = new Scalar256();
        for (int i = 0; i < 1000; i++) {
            BigInteger parent = new BigInteger(256, random).mod(order.subtract(BigInteger.ONE))
                    .add(BigInteger.ONE);
            BigInteger tweak = new BigInteger(256, random).mod(order);
            byte[] parentBytes = scalar(parent);
            byte[] tweakBytes = scalar(tweak);
            byte[] actual = new byte[32];
            BigInteger expected = parent.add(tweak).mod(order);
            boolean accepted = addition.add(parentBytes, (short) 0, tweakBytes, (short) 0,
                    actual, (short) 0);
            check(accepted == (expected.signum() != 0), "ScalarStatusTie");
            equal(actual, scalar(expected), "ScalarValueTie");
            boolean alias = addition.add(parentBytes, (short) 0, tweakBytes, (short) 0,
                    parentBytes, (short) 0);
            check(alias == accepted, "ScalarAliasStatus");
            equal(parentBytes, actual, "ScalarAliasValue");
        }
        byte[] one = scalar(BigInteger.ONE);
        byte[] minusOne = scalar(order.subtract(BigInteger.ONE));
        byte[] actual = filled(32, (byte) 0x55);
        check(!addition.add(minusOne, (short) 0, one, (short) 0, actual, (short) 0),
                "ScalarZeroSumRejected");
        equal(actual, new byte[32], "ScalarZeroSumWiped");
        check(!addition.add(one, (short) 0, Scalar256.ORDER, (short) 0, actual, (short) 0),
                "ScalarOrderTweakRejected");
        equal(actual, new byte[32], "ScalarRejectedOutputWiped");
        check(addition.add(one, (short) 0, new byte[32], (short) 0, actual, (short) 0),
                "ScalarZeroTweakAccepted");
        equal(actual, one, "ScalarZeroTweakIdentity");
    }

    private static byte[] filled(int length, byte value) {
        byte[] output = new byte[length];
        Arrays.fill(output, value);
        return output;
    }

    private static void cleanup() {
        byte[] shaScratch = new byte[Sha512.SCRATCH_BYTES];
        byte[] hmacScratch = new byte[HmacSha512.SCRATCH_BYTES];
        byte[] scalarScratch = new byte[Scalar256.SCRATCH_BYTES];
        Sha512 sha = new Sha512(shaScratch);
        HmacSha512 hmac = new HmacSha512(sha, hmacScratch);
        Scalar256 addition = new Scalar256(scalarScratch);
        byte[] key = scalar(BigInteger.ONE);
        byte[] output = new byte[64];
        sha.digest(key, (short) 0, (short) 32, output, (short) 0);
        equal(shaScratch, new byte[shaScratch.length], "ShaSuccessScratchWiped");
        hmac.compute(key, (short) 0, (short) 32, key, (short) 0, (short) 32,
                output, (short) 0);
        equal(shaScratch, new byte[shaScratch.length], "HmacHashScratchWiped");
        equal(hmacScratch, new byte[hmacScratch.length], "HmacSuccessScratchWiped");
        addition.add(key, (short) 0, key, (short) 0, output, (short) 0);
        equal(scalarScratch, new byte[scalarScratch.length], "ScalarSuccessScratchWiped");
        try {
            sha.digest(key, (short) -1, (short) 32, output, (short) 0);
            throw new AssertionError("ShaBoundsNotRejected");
        } catch (ArrayIndexOutOfBoundsException expected) {
            assertions++;
        }
        equal(output, new byte[64], "ShaRejectOutputWiped");
        equal(shaScratch, new byte[shaScratch.length], "ShaRejectScratchWiped");
        try {
            hmac.compute(key, (short) 0, (short) 32, key, (short) 0, (short) 65,
                    output, (short) 0);
            throw new AssertionError("HmacBoundsNotRejected");
        } catch (ArrayIndexOutOfBoundsException expected) {
            assertions++;
        }
        equal(output, new byte[64], "HmacRejectOutputWiped");
        equal(shaScratch, new byte[shaScratch.length], "HmacRejectHashWiped");
        equal(hmacScratch, new byte[hmacScratch.length], "HmacRejectScratchWiped");
        byte[] partial = filled(10, (byte) 0x55);
        Wipe.clear(partial, (short) 2, (short) 6);
        equal(partial, new byte[] {0x55, 0x55, 0, 0, 0, 0, 0, 0, 0x55, 0x55},
                "WipeExactSubrange");
        Wipe.clear(partial);
        equal(partial, new byte[10], "WipeWholeOwner");
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 0) {
            throw new AssertionError("UnexpectedVectorArgument");
        }
        Random publicInputs = new Random(123456);
        knownAnswers();
        shaTies(publicInputs);
        hmacTies(publicInputs);
        scalarTies(publicInputs);
        cleanup();
        System.out.println("QK-PURE-VECTORS PASS assertions=" + assertions);
    }
}
