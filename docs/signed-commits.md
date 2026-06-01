# Signed Commits

How to sign commits for `zenchron-foundry`, and the honest scope of what signing
does and does not give you.

> We do **not** enforce signed commits in any workflow yet, because enforcement
> is only configured/tested once all contributors sign. Documenting now, enforce
> later (see "When to enforce").

## Why sign

- **Author authenticity / non-repudiation**: a verified commit proves it came
  from a key the author controls, not someone spoofing `user.email`.
- **Tamper-evidence in history**: rewritten/forged commits show as unverified.
- A prerequisite for the branch-protection "Require signed commits" control.

## Why it is helpful but NOT sufficient

- Signing proves **who committed**, not that the **content is safe**. A signed
  commit can still introduce a vulnerability — code review, CI gates, secret
  scanning, and image signing remain essential.
- It does not protect the build/release path; that is covered by branch
  protection + keyless **image** signing (see
  [release-governance.md](release-governance.md)).
- A leaked signing key forges valid signatures — protect keys, prefer hardware
  (YubiKey) or SSH keys with a passphrase.

## Option A — SSH signing (simplest)

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Add the **same** SSH key to GitHub as a **Signing key** (Settings → SSH and GPG
keys → New SSH key → key type *Signing Key*). An auth key and a signing key are
separate entries even if it is the same key.

## Option B — GPG signing

```bash
gpg --full-generate-key                      # ed25519 or rsa4096
gpg --list-secret-keys --keyid-format=long   # find KEYID
git config --global user.signingkey <KEYID>
git config --global commit.gpgsign true
git config --global gpg.program gpg
# export and add the public key to GitHub (Settings -> SSH and GPG keys -> New GPG key):
gpg --armor --export <KEYID>
```

On macOS, install `pinentry-mac` so GPG can prompt for the passphrase.

## GitHub vigilant mode

Enable **Settings → SSH and GPG keys → Flag unsigned commits as unverified
(vigilant mode)**. Then every commit not signed by a registered key is shown as
**Unverified**, making gaps visible even before enforcement.

## Local verification

```bash
git log --show-signature -1          # shows "Good signature"
git verify-commit HEAD               # exit 0 if verified
git config --get commit.gpgsign      # -> true
```

On GitHub, verified commits show a green **Verified** badge.

## When to enforce

Turn on branch protection → **Require signed commits** only after:

1. Every active contributor has a signing key registered on GitHub and
   `commit.gpgsign=true` locally.
2. CI/bot commits (Dependabot, release automation) are accounted for — Dependabot
   commits are signed by GitHub automatically; verify they pass.
3. A test PR with a signed commit merges cleanly under the rule.

Enabling it before that blocks all merges. Track this in
[repository-security.md](repository-security.md) (the box is intentionally left
off until ready).

## Note on this repository's own history

Commits in this repo are currently **unsigned** (no signing key was configured in
the working environment). This is a known gap, called out in the audit; configure
signing per Option A/B before enabling enforcement.
