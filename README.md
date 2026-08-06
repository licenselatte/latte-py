# latte-py

Python SDK for [LicenseLatte](https://licenselatte.com), the software
licensing platform. An idiomatic, from-scratch Python implementation of
license activation and verification.

**Read the [Threat Model](#threat-model) section below before relying on
this package for anything security-sensitive.**

> [!NOTE]
> The Python SDK versions independently from the other language bindings and follows semver. It's currently on v0.x, meaning the public API may still change without a major version bump. It moves to 1.0.0 once the API is validated across real integrations.

---

## What this package verifies

LicenseLatte licenses are issued as a chain of Ed25519-signed JWTs:

```
Master (root, hardcoded in the SDK)
  -> Submaster cert
       -> Project cert
            -> Daily cert
                 -> Activation token (what you actually check against a machine)
```

Each link is a standard compact-serialization JWT
(`base64url(header).base64url(payload).base64url(signature)`, `alg: EdDSA`,
signed with Ed25519, see [RFC 8037]). Verifying a license means:

1. Verify the submaster cert's signature against the hardcoded master public
   key, extract the submaster's own public key from its `spk` claim.
2. Verify the project cert's signature against the submaster's public key,
   extract `ppk`.
3. Verify the daily cert's signature against the project's public key,
   extract `dpk`.
4. Verify the activation token's signature against the daily key.
5. Cross-check the claims (project ID agreement, timing consistency between
   the activation token and the daily cert that signed it).
6. Apply grace-period math: is the token still within its hard expiry, and,
   if the device has been offline, still within its configured grace
   window (30–90 days, chosen when the license is issued)?

This is a standard certificate-chain-of-trust design (the same shape as an
X.509 chain, just JWTs instead of X.509 certs), documented publicly here per
Kerckhoffs's principle: the *mechanism* is not the secret, the master
private key is. This SDK ships only the master **public** key; key rotation
cadence, key storage, and the tooling that issues certs are intentionally
not documented in any SDK repo.

[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037

## Cryptography

- **Ed25519** signature verification via `cryptography`'s hazmat primitives
  (`cryptography.hazmat.primitives.asymmetric.ed25519`): an audited,
  widely used library; no hand-rolled crypto anywhere in this package.
- JWT compact-serialization parsing is hand-written (`src/latte/jwt.py`):
  this is structural (base64url + JSON), not cryptographic, so
  implementing it directly instead of pulling in a general-purpose JWT
  library is a reasonable, minimal-dependency choice for four call sites
  with one fixed algorithm.

## Installation

```sh
pip install -e .
```

## Quick start: activating a license

```python
from latte import Config, Sdk, LatteError

sdk = Sdk(Config(app_id="pk_live_..."))  # from the LicenseLatte dashboard

try:
    lic = sdk.activate("USER-PROVIDED-LICENSE-KEY", "opaque-machine-id")
    print("license OK, expires", lic.expires_at)
    if lic.in_grace_period:
        print("warning: offline a while, please reconnect soon")
    # Keep lic.activation_id around (in your own storage) so you can call
    # sdk.renew(lic.activation_id, ...) later.
except LatteError as e:
    print("activation failed:", e)
```

By default, a successful `activate`/`renew` is written to an on-disk
cache, and a later `activate` call for the same key returns the cached
result without a network round trip as long as it's still valid. There's
no background renewal: call `renew` yourself on whatever schedule fits
your application. Set `Config(cache=False)` to disable the cache entirely
(e.g. a sandboxed environment with no writable filesystem).

## Checking a cached activation without a network call

```python
from latte import LicenseExpiredError, NotActivatedError

try:
    lic = sdk.check("opaque-machine-id")
    print("license OK, expires", lic.expires_at)
except LicenseExpiredError:
    print("license expired, please renew")
except NotActivatedError:
    print("not activated, call activate()")
```

## The cache file

By default, `Sdk` stores an activated license as a small JSON file under
your OS's per-user config directory (via `platformdirs`), named
`{project_key}.json`:

```json
{
  "timestamp": 1700000000,
  "token": "<activation JWT>",
  "submaster": "<submaster cert JWT>",
  "project": "<project cert JWT>",
  "daily": "<daily cert JWT>"
}
```

Writes go to a temp file in the same directory and get renamed into place,
so a crash or a concurrent write can't leave a half-written file behind.
`Config.cache_path` overrides the location if you want it somewhere else.

## Re-verifying a token you're storing yourself

If you'd rather manage persistence yourself instead of using the built-in
cache, `check_license_at`/`check_license` run the same verify+validate
pipeline `Sdk.activate`/`Sdk.check` do, against a token/chain you already
have:

```python
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from latte import check_license, CertChain, VerifyError, ValidateError

master_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(MASTER_PUBLIC_KEY_HEX))
chain = CertChain(submaster=..., project=..., daily=...)

try:
    lic = check_license(master_pub, token, chain, machine_id)
    print("license OK, expires", lic.expires_at)
    if lic.in_grace_period:
        print("warning: offline a while, please reconnect soon")
except VerifyError as e:
    print("could not verify license:", e)  # chain/signature/format problem
except ValidateError as e:
    print("license rejected:", e)  # verified fine, but expired/out of grace/wrong machine
```

`check_license_at(..., now)` is also available for callers who want to pass
an explicit timestamp instead of the real system clock: this is what makes
this package's test suite fully reproducible against a fixed set of test
vectors in `testdata/`.

## Offline grace period

The grace period is an offline tolerance window measured **from the
license's last issuance/renewal**, not from its expiry:

```
issued_at ------------------------------------> expires_at
              |                   |
              └── grace_period ───┘
                  ^ offline window
```

While `now <= issued_at + grace_period`, the license is still usable without
a network call. Once that deadline passes, verification raises
`GraceExpiredError`; once `now > expires_at`, it raises `HardExpiredError`
(checked first: hard expiry always wins).

`PublicLicense.in_grace_period` is a softer, earlier warning signal: it
turns `True` once more than 60 minutes have passed since the last
issuance/renewal without a fresh one arriving, while still inside the grace
window: surface it as a "please reconnect soon" hint, distinct from an
outright rejection.

## What this package does *not* do

OS-level machine-ID fingerprinting and background renewal scheduling are
intentionally out of scope. Pass your own machine-ID string into
`activate`/`renew`/`check`/`check_license`; only the opaque string compared
against the token's `mid` claim matters, not the algorithm that produces
it. For renewal, there's no scheduler here: `Sdk.renew` is the building
block; call it on a timer, in response to a UI action, or whatever fits
your application.

## Threat model

**Read this before you rely on `latte-py` for anything where tamper
resistance, not just cryptographic correctness, matters.**

This is a statement of fact about the architecture, not a disclaimer to
skim past:

- Python source and compiled bytecode (`.pyc`) ship human-readable or
  trivially decompilable. Anyone with a text editor and basic familiarity
  with Python can open your application's installed package, find the call
  to `check_license`/`check_license_at`, and delete it, or monkeypatch
  `latte.check_license` to always return a fabricated `PublicLicense`
  before your application code ever runs. This requires no reverse
  engineering tools beyond a text editor: this is fundamentally different
  from a compiled binary (Go, Rust, C, C++, D), where bypassing a license
  check requires actual binary patching or a debugger.
- This is a known, accepted tradeoff for an interpreted-environment SDK,
  not a bug in this package. **No amount of obfuscation, code-signing the
  `.py` files, or "clever" runtime tricks closes this gap**: Python's
  execution model means the interpreter always has the actual source (or
  bytecode, which trivially decompiles back to source) available to
  inspect and modify at runtime.
- What this package *does* guarantee: the cryptographic verification
  itself is correct. A forged license (wrong signature, broken chain,
  tampered claims) will fail verification exactly as it would in
  `latte-go`, `latte-rs`, or `latte-c`. What it does *not* guarantee is
  that a determined user can't simply remove the call to this package
  from your application entirely.
- **If this distinction matters for your deployment** (e.g. you're
  protecting revenue from a motivated, technically capable user base, not
  just casual copying), the mitigation is **server-side re-validation** —
  but only if you draw the trust boundary in the right place. The
  mitigation isn't "run the check again" (a re-run of `check_license` is
  just as patchable as the first run, and a text editor doesn't care how
  many times you call the function you're deleting). It's "run the check
  somewhere the attacker's text editor can't reach": on your server,
  invoked by your server's own code, gating a resource your server
  actually controls (an API response, a file download, a feature flag
  your backend decides). A locally-patched client can lie to itself all
  day; it can't make your server hand over a server-mediated resource
  without the server independently confirming a valid, unexpired license
  first.
  - This only holds if the server does its own verification. If your
    server instead just *trusts* something the client reports (a
    `"licensed": true` field, a header, a cached result), you've moved
    the trust boundary back onto the attacker's machine and you're back
    to square one — that flag is exactly as easy to fabricate as deleting
    the local check was.
  - `GracePeriod`/`in_grace_period` are what your server uses to decide
    *when* to insist on a fresh activation check, not a mechanism that
    makes a client-side check itself tamper-resistant.
- This tradeoff is specific to Python (and, separately, to Electron/JS;
  see `latte-js`'s equivalent Threat Model section). The compiled SDKs
  (`latte-go`, `latte-rs`, `latte-c`, and C++/D bindings) require actual
  binary reverse engineering to bypass, which is a meaningfully higher bar
  even though none of them are literally unbreakable either.

## Testing

```sh
pip install -e ".[dev]"
pytest
```

Runs unit tests for the checksum algorithm and AppID parsing, chain
verification (valid chains, tampered signatures, broken intermediate links,
cross-check failures, clock-skew edge cases), grace-period math (including
exact boundary conditions), plus the full shared cross-language fixture
suite in `testdata/` (see `../latte-testvectors/README.md`).

```sh
ruff check .
mypy src
```

## License

MIT, see [LICENSE](LICENSE).
