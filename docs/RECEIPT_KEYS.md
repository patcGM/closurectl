# Receipt key management

Receipt keys attest who signed a scoped observation artifact; they do not make
the provider observation true.

- Generate Ed25519 keys on a known-clean machine.
- Keep private keys outside the incident host and repository.
- Record the v2 `signing_key_fingerprint` in the incident record before sharing
  a receipt.
- Distribute public keys over a channel independent of the receipt.
- Use a separate key for disposable drills and real incidents.

To rotate a key, generate new paths (key generation never overwrites an
existing file), publish the new public-key fingerprint, and retain old public
keys for verification of historical receipts. Never re-sign an old receipt
with a new key; create a new receipt with a new `issued_at` and evidence if a
new attestation is required.

If a private key may be compromised, stop using it, preserve its public key for
historical verification, document the compromise time, and treat receipts
issued after that time as untrusted until independently reviewed.
