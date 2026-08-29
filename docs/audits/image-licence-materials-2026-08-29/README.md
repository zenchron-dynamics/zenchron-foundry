# In-image licence and copyright material — the 20 accepted production children

**Run date:** 2026-08-29 · **Source revision under evidence:** `7061caafb3ea09bd5b2342a1daf022151b33f822` ·
**#120 action N1.** Nothing was built, no Dockerfile ran, no package manager ran,
no image was mutated, no mutable tag was read and no SBOM was regenerated.

## 1. What N1 is, and what it is not

The notice bundle already carries the canonical SPDX text of every identifier the
cohort resolves — the text of `GPL-2.0` as SPDX publishes it. That is a different
artifact from `busybox`'s own copyright statement, or from the Debian
`copyright` file recording who holds copyright in **this** build of **this**
package. `retain-copyright-notice` is an obligation about the second, and before
this run no control in the repository had read a byte of one.

**`/usr/share/doc/<pkg>/copyright` is not universal coverage**, and the
accounting below is built so that claiming it would be visible as a lie:

| ecosystem | what the image actually ships |
|---|---|
| Debian | one `copyright` per binary package — sometimes a symlink to a sibling package's file, sometimes a symlinked *directory*, sometimes chained through two, frequently deferring to `/usr/share/common-licenses/<NAME>` |
| Alpine | **nothing.** apk strips documentation. The package database carries an `L:` field, which is a licence *identifier* — not a copyright notice and not a licence text |
| Go | modules are compiled into a binary; a runtime image carries no vendored licence tree, so no path was ever expected |
| PHP | the interpreter and the extensions built by `docker-php-ext-install` are not dpkg-managed and leave nothing behind; PEAR components do, under `/usr/local/lib/php/doc/` |

## 2. How the images were opened

Registry HTTP API only. For every child, three facts were checked before a single
byte was attributed to it, and any one disagreeing is a refusal:

* the **manifest bytes were re-hashed** and had to equal the accepted digest —
  the registry's own claim is not the check;
* the **config blob's own `os`/`architecture`** had to equal the platform the
  accepted run recorded;
* every **layer blob** had to hash to the digest its manifest names.

Layers were read as tar streams in memory with **overlayfs whiteout semantics
applied**: later layers replace earlier ones, `.wh.<name>` deletes, and
`.wh..wh..opq` clears a directory. Reporting a copyright file that a later layer
deleted would be reporting a file that is not in the image.

Extraction tool: `scripts/license/extract-image-licence-materials.py`, sha256 `4856769accbe15bbebcea73f87adf9d0932f1cf3080ed92d9ac110f4c7ce9218`.

## 3. The children

| image | platform | immutable digest | material records |
|---|---|---|---|
| `caddy/prod` | `linux/amd64` | `sha256:384c166402dad573ea2b616ef0af6e40d9b15bd9371193ca6244f0241fccacd8` | 4 |
| `caddy/prod` | `linux/arm64` | `sha256:0dd4b80108f81fcf4dca4c6c98924b7fef913a186c9f92231579d442cd2b9858` | 4 |
| `nginx/prod` | `linux/amd64` | `sha256:bf8e662ddcfc986b9a859217adf7e826e3f1d186914f8bf3a36cf9c5eee82828` | 116 |
| `nginx/prod` | `linux/arm64` | `sha256:2a0775971ea58491207e6287ce8897133e22bab2b36053bf515d2e55fbfe01d2` | 116 |
| `php-cli/8.3` | `linux/amd64` | `sha256:9a598e747d4710492a0be60dfff422cc08db5d193e0980cdf235e53736584988` | 151 |
| `php-cli/8.3` | `linux/arm64` | `sha256:5e0f95bdd570c181e21d0d6ef837d27de9658f92aecab40c2d4dc548a3ca24dd` | 151 |
| `php-cli/8.4` | `linux/amd64` | `sha256:124887dda8667be5a26711c675af7b466fd98c4a4a63d2fb93fb06053cb75d23` | 151 |
| `php-cli/8.4` | `linux/arm64` | `sha256:6e885b182b8082fa8a76bcc4d465094caa3725be5acf3216b3dc88e590222a76` | 151 |
| `php-fpm/8.3` | `linux/amd64` | `sha256:ca9acdf0adc5179d80d712cedc141d810bf719e8db692c4c527557ba50b89d46` | 151 |
| `php-fpm/8.3` | `linux/arm64` | `sha256:bea8ee4d6033b56ad3bd8621284e4d1298ca5b477469423ad02934bade02cf0b` | 151 |
| `php-fpm/8.4` | `linux/amd64` | `sha256:8eab0f293935f717f07a33906aa4ea060acfcf75f21395219d5208adfda0ff6b` | 151 |
| `php-fpm/8.4` | `linux/arm64` | `sha256:ae52345c2851b896f981f67f451f18cb14b409a9c0f71df2546be78561e54ec8` | 151 |
| `php-frankenphp/8.3` | `linux/amd64` | `sha256:54992c07f9dc27e5bff59bd413f19f2416014537f3dc9f782d5a90833dd6edcb` | 207 |
| `php-frankenphp/8.3` | `linux/arm64` | `sha256:f42f06b143c7ff154e0c055076864871b9962ca6a7eec540eab6454e7b65f43b` | 207 |
| `php-frankenphp/8.4` | `linux/amd64` | `sha256:abbb0bec12d80d26878811b1a487dd5c1962103a94d043fd313fa7b99639159f` | 207 |
| `php-frankenphp/8.4` | `linux/arm64` | `sha256:2daeb138033eb251a9a83fc4f0eb01a76aacebb6aab3c11d6ca1c08036225603` | 207 |
| `php-worker/8.3` | `linux/amd64` | `sha256:d35023c581faa639999878e3e48c8a187ed66611cac80bda5a97bdcc738037ba` | 152 |
| `php-worker/8.3` | `linux/arm64` | `sha256:5188a56952b0d5c610255bd5945aef14ab39d168b116738109a2048516d9b934` | 152 |
| `php-worker/8.4` | `linux/amd64` | `sha256:7627fae4d7b144c94e95e4863deb9a99195bbfb46d840673e75b4b328c1b0d64` | 152 |
| `php-worker/8.4` | `linux/arm64` | `sha256:33aaa754c4c60eebce844411e5eb334cee53d07045ba564a04058081d5ea39db` | 152 |

**2884 material records** across the cohort. Identical material sets are stored
once — the twenty children collapse onto **12 distinct sets**, and the captured
bytes collapse onto **152 distinct files** by content hash, of which **137** are
licence or copyright text and are carried.

The two records are emitted with one-space indentation and with repeated strings
interned (reason texts, child keys, material sets). That is not cosmetic: the
repository blocks any file over 512 KB, and the first draft of these records was
1.4 MB and 2.2 MB. The limit is the storage-discipline control working, and the
fix was to make the records compact rather than to route around it.

## 4. Material accounting — 535 implicated components

Every component implicated by the substantive licence backlog gets exactly one
classification. The tool refuses if they do not reconcile.

| class | components |
|---|---|
| `extracted` | 191 |
| `ambiguous` | 1 |
| `absent` | 22 |
| `path-expected-unavailable` | 0 |
| `non-package-managed` | 320 |
| `legal-review-required` | 1 |

```text
implicated = extracted + ambiguous + absent + non-package-managed + legal-review-required
535 = 191 + 1 + 22 + 320 + 1
```

`absent` is the union of *absent* (the ecosystem ships no such material and no
path was expected) and *path-expected-unavailable* (the convention applies and
the file is missing). Both sub-counts are reported; the second is **0**.

### What the two residual findings are

* **`gzip@1.12-1` — ambiguous.** Its copyright file defers to
  `/usr/share/common-licenses/GFDL-3`, and Debian ships no such file: the image
  carries `GFDL`, `GFDL-1.2` and `GFDL-1.3`. This is an upstream defect in the
  package's own copyright file, it is real, and it is left refusing rather than
  papered over by guessing which GFDL was meant.
* **`../@UNKNOWN` — legal-review-required.** A nameless binary-cataloguer
  artifact. Whether it denotes a distributed component at all cannot be decided
  from the image, so neither can what it owes.

### Two defects this run found in its own first pass

Both were caught by reading the output rather than by a failing test, and both
are fixed in the shipped tools:

1. **Chained doc-directory symlinks.** Debian links a whole doc directory at a
   sibling's, and it chains: `binutils-x86-64-linux-gnu` → `libbinutils` →
   `binutils-common`. A resolver that followed one hop reported 19 installed
   packages as missing a copyright file the image ships two indirections away.
2. **The common-licences reference regex** swallowed the sentence-ending period,
   so `see /usr/share/common-licenses/GPL-2.` resolved to `GPL-2.` and 24
   packages were reported as deferring to a file sitting in the image all along.
   References are now resolved against the names the image actually ships.

## 5. What is carried, and what is not

`third-party/image-licence-materials/` carries **137 distinct files,
1456.8 KB**, content-addressed: a copyright file shared by many packages across
eighteen children is stored once and every consumer is bound to its hash.

The installed-package databases and distro-identity files are **not** carried.
They are evidence for the mapping, not material an obligation requires
preserving, and they are two thirds of the extracted bytes. Their sha256 values
stay in the extraction manifest, so the mapping remains checkable by
re-extraction.

## 6. Files

| file | what it is |
|---|---|
| `image-licence-materials.json` | every material record, per child, with its layer, type, symlink target and hash |
| `image-licence-accounting.json` | the 535-component classification, with each symlink chain that had to be followed |
| `SHA256SUMS` | checksums for both |

## 7. What this run did not establish

It carried copyright notices. It did **not** decide any licence question, select
an outbound licence, approve a source-offer mechanism, or authorize
distribution. `policies/license-policy.yaml` is untouched and
`publication.decision` is still `undetermined`.
