package com.isc.sentinel.vendor.luna;

/**
 * Manual TR-31 chain runner. Wrap a working key into a key block under a KBPK,
 * then unwrap it back and confirm the recovered key matches.
 *
 * Usage:  Tr31Demo <B|D> <kbpkHex> <workingKeyHex>
 *   B = 3DES key block (KBPK 16/24 bytes), D = AES key block (KBPK 16/24/32 bytes)
 *
 * Example (AES):
 *   java -cp target/classes:target/test-classes com.isc.sentinel.vendor.luna.Tr31Demo \
 *     D 88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6 \
 *     0123456789ABCDEF0123456789ABCDEF
 */
public final class Tr31Demo {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("usage: Tr31Demo <B|D> <kbpkHex> <workingKeyHex>");
            System.exit(2);
        }
        Tr31Codec.Version v = Tr31Codec.Version.valueOf(args[0].toUpperCase());
        byte[] kbpk = Tr31Codec.unhex(args[1]);
        byte[] key  = Tr31Codec.unhex(args[2]);

        // usage D0 (data), algo A(AES)/T(3DES), mode B(enc+dec), export E. Length filled by codec.
        String headerNoLen = (v == Tr31Codec.Version.D) ? "D0000D0AB00E0000" : "B0000D0TB00E0000";

        System.out.println("KBPK (" + kbpk.length + "B)   : " + Tr31Codec.hex(kbpk));
        System.out.println("working key (" + key.length + "B): " + Tr31Codec.hex(key));

        String block = Tr31Codec.wrap(v, kbpk, headerNoLen, key);
        System.out.println("TR-31 block       : " + block);
        System.out.println("  header          : " + block.substring(0, 16));

        Tr31Codec.Unwrapped u = Tr31Codec.unwrap(kbpk, block);
        System.out.println("recovered key     : " + Tr31Codec.hex(u.key));
        boolean ok = Tr31Codec.hex(u.key).equals(Tr31Codec.hex(key));
        System.out.println(ok ? "ROUND-TRIP OK" : "MISMATCH");
        System.exit(ok ? 0 : 1);
    }
}
