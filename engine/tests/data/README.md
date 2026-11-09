# The signed-manifest fixture

`update-manifest.json` is a manifest body, and `update-manifest.pkcs7` is a detached
PKCS#7 signature over exactly those bytes — the shape `scripts/sign.ps1 -DataFile`
writes beside `dist\update.json` (D-047). `signature.rs`'s test
`a_real_detached_signature_verifies_over_exactly_those_bytes` verifies it, and flips
one byte to prove a changed manifest does not.

- The certificate inside is `CN=MI CS Update Fixture`, self-signed, valid for a
  century, thumbprint `f34c6d80ebaa3bf5110d343adeb37718f539da35` (SHA-1, lowercase —
  what the pin is compared in). **Its private key was never kept**: a signature is
  verifiable without it, and nothing in this repository can sign as it again.
- Nothing here is a secret, a release artifact or a machine value: the `url` points at
  `example.invalid` and the `sha256` is 64 zeros, because the test is about the
  signature, not about the manifest's hashes.
- Regenerating either file is a deliberate act: the thumbprint is part of the test, so
  new bytes need the constant in `signature.rs` updated with them. Mint one with
  `CertificateRequest.CreateSelfSigned` + `SignedCms.ComputeSignature` (SHA-256,
  `X509IncludeOption::EndCertOnly`) — `scripts/verify-update.ps1`'s
  `New-ProbeCertificate` / `New-DetachedSignature` are the same two steps.
