/**
 * Generate Nostr identities for the stack, as shell assignments.
 *
 * Run inside a throwaway `oven/bun` container by bootstrap.sh, so the host
 * needs no Node, no Bun and no toolchain at all. Output is `eval`'d, which is
 * why it emits assignments rather than JSON — parsing JSON in POSIX sh would
 * mean depending on jq.
 *
 * Every value is bech32 or lowercase hex, so single-quoting is total: there is
 * no character in the output that could close the quote.
 *
 * Usage: keygen.ts <count>
 */
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";

const count = Number(process.argv[2] ?? "1");

if (!Number.isInteger(count) || count < 1) {
  console.error("usage: keygen.ts <count>");
  process.exit(1);
}

for (let i = 1; i <= count; i++) {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);

  console.log(`NSEC_${i}='${nip19.nsecEncode(sk)}'`);
  console.log(`NPUB_${i}='${nip19.npubEncode(pk)}'`);
  // Hex, not npub: ditto-relay's MASTER_PUBKEYS is hex-only. The client's
  // VITE_NOSTR_PUSH_PUBKEY accepts either, so hex serves both.
  console.log(`HEX_${i}='${pk}'`);
}
