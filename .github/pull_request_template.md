## Evidence

- [ ] I ran `npm ci --ignore-scripts`, `npm test`, `npm run self-test:source`, and `npm run build`.
- [ ] I added a negative test for every new guard or rejection path.
- [ ] I updated English and Russian documentation together, or explicitly identified the translation gap.
- [ ] This change adds no runtime dependency, or the PR explains why the added attack surface is necessary.
- [ ] Crypto dependency changes include the old/new compatibility output and upstream diff review.
- [ ] Changes under `build/`, `.github/`, key fingerprints, or crypto code received security-focused review.
- [ ] No real mnemonic, entropy, private key, signing key, token, or credential appears in tests or logs.

## Security impact

Describe which invariant changes, the command that demonstrates it, and what must fail if the implementation is defective.
