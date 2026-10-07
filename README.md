# dsh-plugin-reverse

A JavaScript reverse-engineering toolkit for DeepSeek Harness: **assess the route first, then deliver a result along that route**.

**English** · [简体中文](./README.zh-CN.md)

- **Static restoration (the main path)**: turn extracted obfuscated front-end JS into
  computation functions that **run standalone in plain Node** — strip `window`/`document`/`navigator`/`canvas`
  host dependencies and smooth over environment differences, so you can compute a signature, encrypt a
  request body or decrypt a response **without a browser and without injecting into a page**.
- **Assisted location**: generate Hook scripts that capture arguments, return values **and call stacks**,
  for debugging, forensics and locating the encryption entry point.
- **Verification**: built-in AES / RSA / MD5 / SHA / HMAC / cyclic XOR / single-byte brute force / big-integer
  modular exponentiation, so you can recompute against a known ciphertext, key or IV immediately.

> **Scope**: this plugin is for **code you are authorised to analyse** — your own projects,
> authorised security testing, malware analysis, CTF, and interoperability research. The tools are
> generic debugging and static-analysis techniques and do not implement targeted bypasses for any
> specific system. Hooks record function arguments and return values and may therefore contain
> credentials; only use them in environments you are authorised to analyse. Do not point this at
> other people's accounts or systems.

---

## 1. Capability matrix

| Tool | Purpose | Typical output |
|---|---|---|
| `rev_assess` | **Run this before every reverse-engineering task**: decides whether hooking is viable and whether static restoration is viable, and gives the blockers and an ordered plan | Markdown assessment report |
| `rev_hook_generate` | Generate a browser-executable Hook script (WebCrypto / CryptoJS / JSEncrypt / network layer + auto-discovery) | Self-contained `.js` script |
| `rev_extract_pure` | **Static restoration**: dependency-closure extraction plus environment injection, producing host-free computation modules | `pure.mjs` / `env.mjs` / `demo.mjs` |
| `rev_deobfuscate` | Semantics-preserving safe rewrites (escape restoration, constant folding, member-access normalisation) plus obfuscation feature detection | Rewritten source + analysis report |
| `rev_crypto_calc` | 20 cryptographic verification operations, covering both standard-library and hand-rolled big-integer paths | Structured verification results |

---

## 2. Installation

Requires Node.js ≥ 24. The built `lib/` output is committed, so installing from GitHub source needs
**no** build approval.

**Option 1 — install directly (recommended; no npm needed on the user side)**

```sh
dsh plugin --profile web add github:wangyin572/dsh-plugin-reverse
```

> This path needs **no npm run and no build approval**: pnpm installs the one real dependency,
> `acorn`, straight from the manifest, while `@deepseek-ai/*` is resolved by the DSH resolution layer
> to the single instance inside the dsh installation. Measured afterwards, the profile's
> `node_modules` holds only `acorn` and this package — no duplicated `@deepseek-ai/*`.

**Option 2 — clone and install locally (when you want to change the code)**

```sh
git clone https://github.com/wangyin572/dsh-plugin-reverse.git
cd dsh-plugin-reverse
npm install                          # runtime dependencies (@deepseek-ai/* and acorn)
dsh plugin --profile web add "$(pwd)"
```

Then restart that profile. To verify it took effect:

```sh
dsh --profile web --dump-config | grep -A3 dsh-plugin-reverse
```

> **In Option 2, `npm install` is not optional.** `dsh plugin add "$(pwd)"` uses `link:`: pnpm only
> creates a symlink and **installs nothing for it**, and this package does not declare `acorn` as a
> peer, so `acorn` can only come from the repository's own `node_modules`. Skipping it fails
> immediately with `Cannot find package 'acorn'` (measured: a bare copy holding only `package.json`,
> `cordis.patch.yml` and `lib/` fails at module import).
> `lib/` is already in the repository and needs no build; run `npm run build`
> and commit the result only after editing `src/`.

After installation the five tools above appear on the model side. The runtime dependencies are
`@deepseek-ai/cordis`, `@deepseek-ai/dsh-tools`, `@deepseek-ai/schemastery` and `acorn`, all published
publicly on npm. Note the tags differ: `dsh-tools@0.2.0-rc.2` is published under the `next` tag,
whereas `cordis` `~4.0.4` and `schemastery` `~3.18.4` resolve from `latest`. The three
`@deepseek-ai/*` packages are declared as `peerDependencies`: the profile resolution layer points them
at the single instance inside the dsh installation (pnpm's `autoInstallPeers` is off in a profile, so no
duplicate instance is installed).

### Prebuilt tarball

`npm pack` produces a ready-to-install tarball containing the already-built `lib/` plus the docs:

```sh
npm pack
dsh plugin --profile web add ./dsh-plugin-reverse-0.1.0.tgz
```

### Being listed by community directories

Community plugin directories auto-discover repositories through the **`dsh-plugin`** GitHub topic
(Settings → Topics, or `gh repo edit --add-topic dsh-plugin`). The crawler reads the `package.json` at
the **repository root**, and this repository already satisfies it:

- `dsh.bundle.patch` points at a relative path inside the repo → `./cordis.patch.yml` ✅
- the repository is public and not archived; `description` becomes the one-line summary ✅

> **Do not add `dsh.profile` here.** The official docs are explicit: a bundle manifest declares
> `dsh.bundle`, a profile manifest declares `dsh.profile`, and **nothing is both**. `dsh.profile`
> belongs to the profile directory's `package.json` and is written by `dsh plugin add`. Some
> installers (such as find-plugin) filter out repositories that mix bundle and profile manifests as
> invalid candidates.

### Configuration

Override by line `id` in the profile's `cordis.patch.yml`:

```yaml
- id: reverse-toolkit
  name: 'dsh-plugin-reverse'
  config:
    maxSourceBytes: 2000000   # maximum source size allowed per analysis, in bytes
    hookLogLimit: 2000        # Hook script log ring-buffer size
    hookAutoDiscover: true    # whether the Hook auto-discovers suspicious functions by default
```

The `config` block is optional; every field has a default.

---

## 3. Usage flow

### 3.1 Always assess first

```
rev_assess(code = <the JS you extracted>)
```

The report reaches one of four conclusions:

| Conclusion | Meaning |
|---|---|
| `static-first` | The code is statically complete and lightly obfuscated → restore it directly |
| `hook-then-static` | Both routes are viable → **hook first to obtain a set of real input→output pairs**, then restore and compare byte by byte |
| `hook-first` | `eval` / `new Function` / `with` present, so the real logic is not statically visible → you can only hook first |
| `blocked` | Insufficient information (e.g. the logic lives in a Worker or WASM); more material is needed |

It also gives an obfuscation score, a feature list, **ranked entry-point candidates**, the environment
values that must be captured, and an ordered execution plan.

### 3.2 Route ①: hook to locate the entry point

```
rev_hook_generate(targets = [{ object: "window", method: "makeSign" }])
```

Save the returned script as a `.js` file and run it in the target page (DevTools console /
Sources → Snippets / CDP `Page.addScriptToEvaluateOnNewDocument`). Afterwards:

```js
__revHook.dump()    // inspect captured records
__revHook.save()    // export as JSON
__revHook.unhook()  // restore all replaced methods
```

Every record carries a **call stack** — the most effective information for locating who calls the
encryption function.

### 3.3 Route ②: static restoration (the main path)

```
rev_assess(code = ...)                    # confirm feasibility first
rev_deobfuscate(code = ...)               # preprocessing: escape restoration / constant folding / member-access normalisation
rev_extract_pure(code = ..., entry = ["makeSign"])
```

Three files are produced; write them to disk and **run them directly** to verify:

```sh
node demo.mjs
```

The shape of `pure.mjs`:

```js
export function createRuntime(env) {
  // host objects are all injected via env, rather than rewriting every reference site
  const { navigator, screen, document, btoa } = env

  // ---- from original file line 4: _0x1a2b (function) ----
  function _0x1a2b(a, b) { /* verbatim source, not rewritten */ }
  // ---- from original file line 17: makeSign (function) ----
  function makeSign(payload) { /* verbatim source, not rewritten */ }

  return { makeSign }
}
```

Call site (no browser involved at all):

```js
import { createRuntime } from './pure.mjs'
import { createEnv } from './env.mjs'

// real captured environment values are injected here
const runtime = createRuntime(createEnv({
  navigator: { userAgent: 'real UA', platform: 'MacIntel' },
  document: { cookie: 'real cookie' },
  screen: { width: 1512 },
}))

console.log(runtime.makeSign('business payload'))
```

### 3.4 Verification

```
rev_crypto_calc(operation = "aes-decrypt", data = "<ciphertext>", passphrase = "passphrase", dataEncoding = "base64")
rev_crypto_calc(operation = "hash", algorithm = "md5", data = "abc")
rev_crypto_calc(operation = "rsa-manual-pow", value = "<m>", exponent = "<e>", modulus = "<n>")
rev_crypto_calc(operation = "xor-brute-force", data = "<hex>")
```

The 20 supported operations: `hash`, `hmac`, `aes-encrypt`, `aes-decrypt`, `openssl-decrypt`,
`openssl-encrypt`, `xor`, `xor-brute-force`, `xor-recover-key`, `rsa-encrypt`, `rsa-decrypt`,
`rsa-sign`, `rsa-verify`, `rsa-public-from-modulus`, `rsa-manual-pow`, `rsa-key-info`,
`mod-pow`, `mod-inverse`, `bigint-parse`, `hex-normalize`.

**Encoding is always explicit** (`utf8`/`hex`/`base64`/`base64url`/`latin1`): the same string
interpreted as hex and as utf8 yields completely different results, and silently guessing only
leads to confidently holding a wrong answer. Invalid hex, odd lengths and wrong-length IVs
**fail loudly** rather than being truncated.

---

## 4. The pure computation core is usable on its own

The core is a **host-dependency-free pure function layer**: it does not import cordis, does not
import DSH and performs no I/O. A project that lists this package as a dependency can use it through
the exposed subpath:

```js
import { aesDecrypt, opensslDecrypt, hmac, xorBytes, rsaManualPow } from 'dsh-plugin-reverse/core'
```

You can also copy the core out entirely: the source is `src/core/` in this repository, and the compiled
`lib/core/index.js` is committed (`npm run build` rebuilds it after you edit `src/`).

It follows exactly the same constraints as this plugin's static-restoration output: no DOM/BOM,
no side effects, runnable standalone.

---

## 5. Project structure

```
src/
├── core/          pure computation core (encoding / hash / aes / rsa / xor / errors)
├── analysis/      static analysis (ast / host / deobfuscate / extract / hook / assess)
├── services/      cordis services (ctx.reverseCrypto / ctx.reverseAnalysis)
├── tools/         the 5 agent tools (defineTool)
└── index.ts       root plugin: registers services and tools
test/
├── core.test.mjs      cryptographic core (including external OpenSSL vectors)
├── analysis.test.mjs  deobfuscation / host detection / closure extraction / Hook / assessment
├── plugin.test.mjs    plugin contract and end-to-end tool chain
└── fixtures/          simulated obfuscated samples
```

Dependencies flow one way only: `tools → services → analysis → core`. The core layer never depends
on DSH in reverse, so "the plugin's core" and "the pure code the plugin produces" obey the same
host-free constraints.

---

## 6. Verification

```sh
npm run build                # TypeScript strict-mode compilation
npm test                     # run the test suite
npm run check                # the two steps above
npm run verify:integration   # real launcher integration check (isolated DSH_HOME, ~1 minute)
npm run verify:all           # everything
```

The integration check creates an isolated `DSH_HOME` under `.dsh-scratch/` in the workspace, builds a
profile from the `web` template shipped with the product, really runs `dsh plugin add`, and asserts
that `--dump-config` contains the line this package contributes and that `--dump-config-schema` can
import this package's modules. The script has a guard rail that refuses to place the temporary home
outside the repository, and never touches the real `~/.dsh`.

A few key assertions in the tests:

- **AES/KDF align with external implementations**: vectors are generated on the spot by the system
  OpenSSL 3.6 (`openssl enc -aes-256-cbc -md md5 -S ... -pass pass:...`), not self-generated and
  self-verified.
- **Semantic equivalence**: the original obfuscated code is run inside a simulated browser in
  `node:vm`, the static-restoration output is run in plain Node, and the two outputs are asserted to
  be **byte-for-byte identical**; it is further asserted that changing an environment value changes
  the result.
- **Generated artifacts are executable**: both Hook scripts and restoration output first pass AST
  syntax validation, then are really executed in a sandbox, asserting "same return value",
  "restorable" and "no module loader required".
- **Plugin contract**: a real cordis mount, asserting that all 5 tools register, both services are
  available, and the parameter validation chain is intact.

---

## 7. Honest boundaries

These are **capability boundaries**, not a to-do list. In these situations the tools explicitly
report a blocker instead of producing code that "runs but computes the wrong thing":

| Situation | Tool behaviour |
|---|---|
| `eval` / `new Function` / `with` | Judged as blocking static restoration; hooking is recommended; reports a `blocker` and generates no code |
| Control-flow flattening | **No automatic reordering** (wrong reordering silently changes semantics); reports the case order for manual reconstruction and lowers confidence to `low` |
| String arrays + decoder functions | Detected and reported only, **not automatically inlined** (inlining before the rotation offset is fully restored amounts to guessing) |
| canvas / WebGL / Audio fingerprints | Cannot be reproduced in Node; `env.mjs` leaves explicit placeholders and lists them under `unmockable`, requiring external capture |
| Environment values that depend on a real browser instance | Produces `MUST_CAPTURE` placeholders and **never fabricates a "plausible" value** |
| The entry point depends on an outer scope that cannot be extracted | Reports an `unresolved-reference` blocker and states which code needs to be supplied |
| Only `(n, e, d)` given, without CRT parameters | A PEM private key cannot be constructed (mathematically requires p and q); use `rsa-manual-pow` to do the modular exponentiation directly instead |

`MUST_CAPTURE` is an **inherent boundary** of static restoration, not an implementation defect: if a
signature mixes in `navigator.userAgent` or a canvas fingerprint, any attempt to "simulate a value"
only yields a signature that looks right but is wrong. The correct approach is to capture it once in
the browser and then inject it.

---

## 8. License

MIT
