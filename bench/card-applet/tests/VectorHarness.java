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
        SoftwareSha512 software = new SoftwareSha512();
        for (int length = 0; length <= 1000; length++) {
            byte[] message = new byte[length];
            random.nextBytes(message);
            byte[] actual = new byte[64];
            sha.digest(message, (short) 0, (short) length, actual, (short) 0);
            equal(actual, MessageDigest.getInstance("SHA-512").digest(message), "Sha512JvmTie");
            byte[] oracle = new byte[64];
            software.digest(message, (short) 0, (short) length, oracle, (short) 0);
            equal(actual, oracle, "Sha512SoftwareTie");
        }
        byte[] maximum = new byte[32767];
        random.nextBytes(maximum);
        byte[] actual = new byte[64];
        sha.digest(maximum, (short) 0, (short) maximum.length, actual, (short) 0);
        equal(actual, MessageDigest.getInstance("SHA-512").digest(maximum), "Sha512MaximumTie");
        byte[] oracle = new byte[64];
        software.digest(maximum, (short) 0, (short) maximum.length, oracle, (short) 0);
        equal(actual, oracle, "Sha512SoftwareMaximumTie");
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
                equal(actual, softwareHmac(key, data), "HmacSoftwareTie");
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

    private static byte[] softwareHmac(byte[] key, byte[] data) {
        SoftwareSha512 software = new SoftwareSha512();
        byte[] inner = new byte[128 + data.length];
        byte[] outer = new byte[192];
        for (int i = 0; i < 128; i++) {
            int value = i < key.length ? key[i] : 0;
            inner[i] = (byte) (value ^ 0x36);
            outer[i] = (byte) (value ^ 0x5c);
        }
        System.arraycopy(data, 0, inner, 128, data.length);
        software.digest(inner, (short) 0, (short) inner.length, outer, (short) 128);
        byte[] result = new byte[64];
        software.digest(outer, (short) 0, (short) outer.length, result, (short) 0);
        return result;
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
        javacard.security.MessageDigest.configure(0, 0, 0, false);
        byte[] shaScratch = new byte[SoftwareSha512.SCRATCH_BYTES];
        byte[] hmacScratch = new byte[HmacSha512.SCRATCH_BYTES];
        byte[] scalarScratch = new byte[Scalar256.SCRATCH_BYTES];
        SoftwareSha512 software = new SoftwareSha512(shaScratch);
        Sha512 sha = new Sha512();
        HmacSha512 hmac = new HmacSha512(sha, hmacScratch);
        Scalar256 addition = new Scalar256(scalarScratch);
        byte[] key = scalar(BigInteger.ONE);
        byte[] output = new byte[64];
        software.digest(key, (short) 0, (short) 32, output, (short) 0);
        equal(shaScratch, new byte[shaScratch.length], "SoftwareShaSuccessScratchWiped");
        sha.digest(key, (short) 0, (short) 32, output, (short) 0);
        hmac.compute(key, (short) 0, (short) 32, key, (short) 0, (short) 32,
                output, (short) 0);
        check(javacard.security.MessageDigest.resetCount() == 6, "HmacHashResetAfterEveryUse");
        check(javacard.security.MessageDigest.finalCount() == 3, "HmacTwoDigestCalls");
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
        try {
            software.digest(key, (short) -1, (short) 32, output, (short) 0);
            throw new AssertionError("SoftwareShaBoundsNotRejected");
        } catch (ArrayIndexOutOfBoundsException expected) {
            assertions++;
        }
        equal(shaScratch, new byte[shaScratch.length], "SoftwareShaRejectScratchWiped");
        try {
            hmac.compute(key, (short) 0, (short) 32, key, (short) 0, (short) 65,
                    output, (short) 0);
            throw new AssertionError("HmacBoundsNotRejected");
        } catch (ArrayIndexOutOfBoundsException expected) {
            assertions++;
        }
        equal(output, new byte[64], "HmacRejectOutputWiped");
        check(javacard.security.MessageDigest.finalCount() == 3, "HmacBoundsBeforeHash");
        equal(hmacScratch, new byte[hmacScratch.length], "HmacRejectScratchWiped");
        byte[] partial = filled(10, (byte) 0x55);
        Wipe.clear(partial, (short) 2, (short) 6);
        equal(partial, new byte[] {0x55, 0x55, 0, 0, 0, 0, 0, 0, 0x55, 0x55},
                "WipeExactSubrange");
        Wipe.clear(partial);
        equal(partial, new byte[10], "WipeWholeOwner");
    }

    private static void exactWipedSlice(byte[] output, String name) {
        equal(Arrays.copyOfRange(output, 8, 72), new byte[64], name + "OutputWiped");
        equal(Arrays.copyOfRange(output, 0, 8), filled(8, (byte) 0x55), name + "PrefixPreserved");
        equal(Arrays.copyOfRange(output, 72, 80), filled(8, (byte) 0x55), name + "SuffixPreserved");
    }

    private static void providerFaults() {
        int[][] digestCases = {{1, 0, 0}, {2, 0, 0}, {-1, 0, 0},
                {0, 1, 0}, {0, 0, 1}, {2, 1, 0}};
        byte[] input = filled(200, (byte) 0x33);
        for (int[] fault : digestCases) {
            javacard.security.MessageDigest.configure(fault[0], fault[1], fault[2], false);
            Sha512 sha = new Sha512();
            byte[] output = filled(80, (byte) 0x55);
            try {
                sha.digest(input, (short) 7, (short) 129, output, (short) 8);
                throw new AssertionError("ProviderFaultNotRejected");
            } catch (RuntimeException expected) {
                assertions++;
            }
            exactWipedSlice(output, "ProviderFault");
            check(javacard.security.MessageDigest.resetCount() == 2, "ProviderFinalResetAttempted");
            check(javacard.security.MessageDigest.finalCount() ==
                    (fault[0] == 1 || fault[0] == -1 ? 0 : 1), "ProviderNoUseBeforeReset");
            check(javacard.security.MessageDigest.requestCount() == 1, "ProviderNoFallbackRequest");
            check(javacard.security.MessageDigest.allocationCount() == 1, "ProviderNoPerUseAllocation");
        }

        int[][] hmacCases = {{1, 0, 0}, {2, 0, 0}, {3, 0, 0}, {4, 0, 0}, {-1, 0, 0},
                {0, 1, 0}, {0, 2, 0}, {0, 0, 1}, {0, 0, 2}, {2, 1, 0}, {4, 2, 0}};
        for (int[] fault : hmacCases) {
            javacard.security.MessageDigest.configure(fault[0], fault[1], fault[2], false);
            byte[] scratch = new byte[HmacSha512.SCRATCH_BYTES];
            HmacSha512 hmac = new HmacSha512(new Sha512(), scratch);
            check(javacard.security.MessageDigest.resetCount() == 0, "HmacConstructionDoesNotReset");
            Arrays.fill(scratch, (byte) 0x44);
            byte[] output = filled(80, (byte) 0x55);
            try {
                hmac.compute(input, (short) 0, (short) 32, input, (short) 32, (short) 37,
                        output, (short) 8);
                throw new AssertionError("HmacProviderFaultNotRejected");
            } catch (RuntimeException expected) {
                assertions++;
            }
            exactWipedSlice(output, "HmacProviderFault");
            equal(scratch, new byte[384], "HmacProviderFaultAllScratchWiped");
            int resets = javacard.security.MessageDigest.resetCount();
            int finals = javacard.security.MessageDigest.finalCount();
            hmac.clear();
            check(javacard.security.MessageDigest.resetCount() == resets, "HmacClearDoesNotReset");
            check(javacard.security.MessageDigest.finalCount() == finals, "HmacClearDoesNotHash");
            check(javacard.security.MessageDigest.requestCount() == 1, "HmacNoFallbackRequest");
            check(javacard.security.MessageDigest.allocationCount() == 1, "HmacNoPerUseAllocation");
        }

        javacard.security.MessageDigest.configure(0, 0, 0, true);
        try {
            new Sha512();
            throw new AssertionError("MissingProviderNotRejected");
        } catch (RuntimeException expected) {
            assertions++;
        }
        check(javacard.security.MessageDigest.requestCount() == 1, "MissingProviderNoFallback");
        check(javacard.security.MessageDigest.allocationCount() == 0, "MissingProviderNoReplacement");

        javacard.security.MessageDigest.configure(0, 0, 0, false);
        Sha512 sha = new Sha512();
        byte[] output = new byte[64];
        for (int i = 0; i < 20; i++) {
            sha.digest(input, (short) 0, (short) 37, output, (short) 0);
        }
        check(javacard.security.MessageDigest.resetCount() == 40, "RepeatedUseResetCount");
        check(javacard.security.MessageDigest.finalCount() == 20, "RepeatedUseHashCount");
        check(javacard.security.MessageDigest.requestCount() == 1, "RepeatedUseOneProviderRequest");
        check(javacard.security.MessageDigest.allocationCount() == 1, "RepeatedUseOneProviderOwner");

        short[][] bounds = {{-1, 1, 8}, {0, -1, 8}, {201, 0, 8}, {199, 2, 8},
                {0, 1, -1}, {0, 1, 17}};
        for (short[] bound : bounds) {
            javacard.security.MessageDigest.configure(0, 0, 0, false);
            sha = new Sha512();
            output = filled(80, (byte) 0x55);
            try {
                sha.digest(input, bound[0], bound[1], output, bound[2]);
                throw new AssertionError("ProviderBoundsNotRejected");
            } catch (ArrayIndexOutOfBoundsException expected) {
                assertions++;
            }
            check(javacard.security.MessageDigest.finalCount() == 0, "ProviderBoundsBeforeHash");
            if (bound[2] == 8) {
                exactWipedSlice(output, "ProviderBounds");
            } else {
                equal(output, filled(80, (byte) 0x55), "InvalidOutputRangeUntouched");
            }
        }
        javacard.security.MessageDigest.configure(0, 0, 0, false);
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
        providerFaults();
        System.out.println("QK-PURE-VECTORS PASS assertions=" + assertions);
    }
}
