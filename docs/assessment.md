# Requirements Assessment and Algorithm Design Analysis

This document answers two questions: **whether each requirement can be met, and to what extent**;
and **why the core algorithms are designed the way they are**.
The governing standard is "rather say it cannot be done than produce code that runs but computes the wrong thing".

**English** · [简体中文](./assessment.zh-CN.md)

---

## 1. Requirements assessment report

### 1.1 Item-by-item feasibility judgement

| # | Requirement | Verdict | Implementation and boundaries |
|---|---|---|---|
| 1 | Assisted location: generate Hook scripts capturing arguments/return values | ✅ Fully feasible | Self-contained browser script covering WebCrypto / CryptoJS / JSEncrypt / encoding layer / network layer + auto-discovery; additionally records the **call stack** for locating the entry point |
| 2 | Static restoration: strip host environment, output independently runnable pure computation functions | ⚠️ **Conditionally feasible** | Fully feasible for code whose "dependency closure is statically determinable" (verified by byte-for-byte comparison in `node:vm`); not feasible for `eval`/`new Function`/`with`, where a blocker is explicitly reported |
| 3 | Smooth over environment differences | ⚠️ **Partially feasible** | "Eliminating dependencies" is feasible (environment injection); "conjuring environment values from nothing" is **not** — see §1.2 |
| 4 | Built-in cryptographic utility functions + fast verification against ciphertext/key/iv | ✅ Fully feasible | 20 operations; AES covers 6 modes and CryptoJS/OpenSSL `Salted__` format; RSA covers both the standard-library path and the hand-rolled big-integer path |
| 5 | Rigorous TS types, minimal `any` | ✅ Fully feasible | Strict mode + `noUncheckedIndexedAccess`; `any` appears only at the single point where acorn types are narrowed, and is commented |
| 6 | Correctly register cordis services | ✅ Fully feasible | Two `Service` subclasses: `ctx.reverseCrypto` / `ctx.reverseAnalysis` |
| 7 | Remove all DOM/BOM dependencies | ✅ Feasible | Output modules reference no host globals; a missed host name **throws ReferenceError immediately** (fails loud rather than silently reading undefined) |
| 8 | Fill in missing global mocks (only what computation needs, no browser-emulation library) | ✅ Feasible | Generates a minimal `env.mjs` containing only the globals actually referenced; **deliberately does not pull in jsdom/happy-dom** |
| 9 | Ship a standalone test demo runnable directly with node | ✅ Fully feasible | Generates `demo.mjs`; `node demo.mjs` just works |
| 10 | Comments annotating algorithm logic and variable provenance | ✅ Feasible | Output modules annotate each symbol's **original file line number**; source slices stay verbatim |
| 11 | Heavy obfuscation / control-flow flattening: lexical preprocessing and deobfuscation first | ✅ Feasible | Escape restoration, constant folding, member-access normalisation (provably semantics-preserving) |
| 12 | Control-flow flattening: extract the core computation branches | ⚠️ **Partially feasible** | Can **identify and output the case order** for manual reconstruction; **does not reorder automatically** (see §1.3) |
| 13 | When full restoration is impossible, output an analysis report + annotate blockers + provide a minimal test harness | ✅ Feasible | `blockers` returned in a structured form; `unresolved` lists unresolvable names; `env.mjs` itself is the minimal usable harness |
| 14 | Do not force-write invalid code | ✅ Implemented | In `eval`/`with` scenarios it **does not generate** a deliverable `pure.mjs`, only a report |
| 15 | Assess Hook feasibility first on every task | ✅ Feasible | `rev_assess` is the first step of the tool chain, outputting a route conclusion + evidence + plan |

### 1.2 The key distinction regarding "smoothing over environment differences"

"Smoothing over environment differences" has two very different meanings, and conflating them turns
the tool into a "wrong-signature generator":

| Type | Examples | Can static restoration handle it |
|---|---|---|
| **Dependency can be eliminated** | `document.addEventListener`, `fetch`, `appendChild`, `alert` | ✅ Stubbed as no-ops, no effect on computation |
| **Value can be deterministically reproduced** | `atob`/`btoa`, `setTimeout`, `TextEncoder`, `location.protocol` | ✅ Uses the real Node equivalent; results match the browser |
| **Value must be captured** | `navigator.userAgent`, `document.cookie`, `screen.width`, canvas/WebGL fingerprints, `performance.now()` | ❌ **Cannot be synthesised**; must be captured from a real browser and injected |

The third category is the **inherent boundary** of static restoration. The tool's approach is to
generate explicit `MUST_CAPTURE` placeholders and leave an injection point via
`createEnv(overrides)` — **not** to invent a "plausible-looking" value. The latter yields a signature
that looks right but is wrong, which is far more dangerous than a plain error.

> This is also why jsdom / happy-dom are explicitly rejected: an emulator supplies **plausible but
> wrong** fingerprint values, disguising "computed incorrectly" as "computed correctly".

### 1.3 Why control-flow flattening is not automatically reordered

Automatically reordering a state machine requires simultaneously determining: the initial value of the
state variable, each case's jump target, the execution order between cases, and whether unreachable
branches exist. Get any one of these wrong and the output code **still runs** — it just computes a
different result. This class of error produces no runtime signal and is extremely hard to detect.

The tool's approach is therefore: **report the `case` order and positions**, lower confidence to
`low`, and let a human decide. The extracted closure remains usable (it contains all branches); only
the execution path needs manual confirmation.

### 1.4 Explicitly not implemented

| Item | Reason |
|---|---|
| Automatically inlining string arrays back to their use sites | The rotation offset is usually determined at runtime; inlining before the decoder function is fully restored amounts to guessing |
| Automatic state-machine reordering | See §1.3 |
| Logic inside WASM / native extensions | Beyond the scope of JS static analysis |
| Constructing a PEM private key from `(n, e, d)` | Mathematically requires p and q; `rsa-manual-pow` is provided as an alternative path |
| SM2/SM3/SM4 (Chinese national algorithms) | Node's built-in crypto does not support them; no third-party implementation was pulled in, to keep the core dependency-free |
| Anti-debugging bypass | Not this tool's responsibility; the Hook script only provides `toString` spoofing to avoid false positives |

---

## 2. Algorithm design analysis

### 2.1 The four-step static restoration pipeline

```
① Parse         acorn → ESTree, trying script and module mode in turn; on failure, a located error with line/column
② Symbol table  Scan declarations at arbitrary depth (obfuscated code often stuffs everything into an IIFE); for duplicate names take the widest scope
③ Closure       Starting from the entry point, recursively collect along free identifiers; assemble using **verbatim source slices**
④ Env injection Insert `const { window, document, ... } = env` at the top of the output module
```

**Why ③ uses verbatim slices**: if nothing is rewritten, there is no rewriting error. Correctness is
guaranteed by the simple property "is this the original text" rather than by a complex set of
transformation rules.

**Why ④ uses environment injection rather than point-by-point rewriting**: replacing each `navigator`
with `env.navigator` requires precisely locating every reference (and distinguishing references from
property names); the more change points, the more room for error. Injection adds **one line** at the
top of the module: every host reference in the source then naturally resolves to `env`. An added
benefit is that Node has no such globals, so if a host name is missed, the runtime throws
`ReferenceError` instead of silently getting `undefined`.

### 2.2 Free-variable computation and scope shadowing

Deciding "is this identifier a host reference" requires ruling out two cases: property names (the
`userAgent` in `navigator.userAgent`) and names shadowed by a local declaration.

- **Reference-position determination**: needs the parent node and key, so the walker carries
  `(node, parent, key)` and excludes non-computed member `property`, non-computed object-literal
  `key`, labels and declaration names.
- **Shadowing determination must be scope-level**: an early implementation merged all declaration
  names in the file into one flat set, so a single `var navigator = …` anywhere caused every
  `navigator` in the file to stop being recognised as a host reference. That is a **dangerous missed
  detection** (a missed environment dependency makes the restoration quietly compute the wrong
  result). It now uses one scope set for the file root plus one per function, checked layer by layer
  along containment.

### 2.3 Three-way classification of environment values

`src/analysis/host.ts` maintains a catalogue of roughly 60 host globals, each tagged
`removable` / `capturable` / `must-capture` / `diagnostic`. The classification determines the
generated stub: deterministically reproducible ones get a real implementation, pure side effects get
a no-op, must-capture ones get an explicit placeholder.

### 2.4 Function attribution of host references

Reporting "which function touches the environment" is extremely valuable for locating the entry point
(signature functions usually read the environment). Attribution uses **interval containment**: all
function ranges are collected up front, and for each reference the smallest containing function is
taken. An early implementation maintained a function stack during traversal, but the walker only had
an enter callback and no exit callback, so the stack never unwound and attribution was necessarily
wrong.

### 2.5 The three iron rules of safe rewriting

1. **Only provably equivalent transformations**: escape restoration re-serialises using the AST's
   already-decoded `value` — the same value written differently; constant folding only handles
   provable cases such as `!0`/`!1`/`void 0`/literal concatenation.
2. **A replacement range must cover the complete syntactic unit**: when turning `obj['abc']` into
   `obj.abc`, the range must include the trailing `]` (otherwise it produces `obj.abc]`) and must
   also cover the leading `[`; optional chaining `a?.['b']` must preserve the `?.`. Both had bugs at
   one point and are now locked down by regression assertions.
3. **For nested replacements take the wider one**: `!![]` plans both "whole ⇒ `true`" and
   "inner ⇒ `false`"; applying in descending `end` order ensures the wider match wins. Descending
   `start` order would produce `!false`.

### 2.6 Compatibility design of the cryptographic core

Front-end AES almost always comes from CryptoJS, which has three unwritten defaults; failing to
reproduce them means "the algorithm is right but it will not decrypt":

1. When passed a string passphrase it derives the subkey via OpenSSL's `EVP_BytesToKey`;
2. The derivation digest defaults to **MD5** (not SHA);
3. The ciphertext carries a `"Salted__" + 8-byte salt` prefix, then is base64-encoded as a whole.

The core therefore provides a `passphrase` mode, a switchable `kdfHash`, and a matching pair
`opensslDecrypt`/`opensslEncrypt`. Correctness is checked against **vectors generated live by the
system OpenSSL**, not self-generated and self-verified.

RSA covers two paths: the standard library path via PEM, and the hand-rolled big-integer path common
in obfuscated code (`m = c^d mod n`, with `modPow` implemented over BigInt), the latter requiring no
PEM to recompute.

### 2.7 Layering and dependency direction

```
tools → services → analysis → core
```

`core` has zero host dependencies, so it can itself be copied into any Node project and used
standalone; it obeys exactly the constraints of "the pure code this plugin produces for users" — the
plugin's own core is a demonstration of that standard.
