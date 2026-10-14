# latte-py

Python SDK for [LicenseLatte](https://licenselatte.com), the software
licensing platform. An idiomatic, from-scratch Python implementation of
license activation and verification.

Full docs: [licenselatte.com/docs/sdks/python](https://licenselatte.com/docs/sdks/python)

**Read the [Threat Model](#threat-model) section below before relying on
this package for anything security-sensitive.**

> [!NOTE]
> The Python SDK versions independently from the other language bindings and follows semver. It's currently on v0.x, meaning the public API may still change without a major version bump. It moves to 1.0.0 once the API is validated across real integrations.

---

## What this package verifies

LicenseLatte licenses are issued as a chain of Ed25519-signed JWTs:

```
Master (root, one of the keys hardcoded in the SDK)
  -> Submaster cert
       -> Project cert
            -> Daily cert
                 -> Activation token (what you actually check against a machine)
```

Each link is a standard compact-serialization JWT
(`base64url(header).base64url(payload).base64url(signature)`, `alg: EdDSA`,
signed with Ed25519, see [RFC 8037]). Verifying a license means:

1. Verify the submaster cert's signature against the hardcoded master public
   keys (it must verify under any one of them), extract the submaster's own
   public key from its `spk` claim.
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
private key is. This SDK ships only the master **public** keys; key rotation
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
    lic = sdk.activate("USER-PROVIDED-LICENSE-KEY")
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

## The machine ID

`Sdk` works out which machine it is running on once, when you construct it,
and uses that for every `activate`, `renew` and `check`. It reads the
platform's own machine ID: `/var/lib/dbus/machine-id` or `/etc/machine-id`
on Linux, `IOPlatformUUID` from `ioreg` on macOS, `MachineGuid` from the
registry on Windows, and `/etc/hostid` or `kenv` on the BSDs. That raw ID
never leaves the machine. What the server sees, and what the token's `mid`
claim holds, is lowercase hex `HMAC-SHA256(key = raw ID, message =
"licenselatte_" + app_id)`, which `sdk.machine_id` exposes.

If no machine ID can be read, the constructor raises `MachineIdError`.

Supply your own raw ID with `Config(machine_id=...)` when the platform's does
not identify one seat:

- containers that share an image's `/etc/machine-id`, or have none;
- cloned VMs, which inherit the image's ID;
- a seat per user rather than per machine (pass a stable user ID);
- tests.

It is hashed the same way, byte for byte with no trimming. Changing it on an
install that is already activated counts as a new machine.

## Checking a cached activation without a network call

```python
from latte import LicenseExpiredError, NotActivatedError

try:
    lic = sdk.check()
    print("license OK, expires", lic.expires_at)
except LicenseExpiredError:
    print("license expired, please renew")
except NotActivatedError:
    print("not activated, call activate()")
```

## Releasing this machine, and listing and naming machines

These calls need the network and take the same `activation_id` and
`license_key` as `renew`:

```python
def deactivate(self, activation_id: str, license_key: str) -> DeactivateResult
def machines(self, activation_id: str, license_key: str) -> list[Machine]
def rename_machine(self, activation_id: str, license_key: str, name: str) -> str

@dataclass(frozen=True)
class DeactivateResult:
    released: bool               # False when it was already released; still success
    seat_free_at: float | None   # unix seconds, set when the seller holds the seat until then

@dataclass(frozen=True)
class Machine:
    name: str | None
    fingerprint: str             # first 12 characters of the machine ID hash
    activated_at: float          # unix seconds
    last_seen_at: float          # last activation or renewal
    seat_free_at: float | None   # set on a released machine whose seat is still held
    current: bool                # the machine this SDK is running on
```

`deactivate` releases this machine's seat so the licence can be activated on
another machine: the "Deactivate" button in your app. The SDK asks the server
to release the seat first and deletes the cached token only once the server
has answered, so `check` raises `NotActivatedError` afterwards until the next
`activate`. If the call fails, nothing changes locally and the user can try
again; the seat is never lost to a dropped connection. Repeating a release
that already went through is success. A machine that is lost, dead or wiped
cannot call this; its seat is released from the seller's customer portal
instead.

On plans with the deactivation policy engine the seller may limit releases.
A refusal raises `DeactivationBlockedError`, whose message is written for the
user, whose `reason` is `"deactivation_cooldown"` or
`"deactivation_limit_reached"`, and whose `available_at` (unix seconds, or
`None`) says when to try again. The seller may also hold the freed seat until
this machine's last token has expired, which `seat_free_at` reports.

```python
from latte import DeactivationBlockedError, LatteError

try:
    sdk.deactivate(activation_id, license_key)
    print("This machine is released.")
except DeactivationBlockedError as e:
    print(e)
except LatteError:
    print("Could not reach the licence server. Nothing was changed; try again when online.")
```

`machines` lists the machines holding a seat on the licence, for showing the
customer where it is in use; it cannot release another machine, which is the
customer portal's job. `rename_machine` names this machine and returns the
name as stored, trimmed; the server refuses a name that is empty, longer than
64 characters or holds control characters (`ServerError`). Both raise
`LicenseExpiredError` when this machine's activation is no longer active.

A machine is named after its hostname (`socket.gethostname()`) when it
activates. `Config(machine_name="...")` sends another name and
`Config(machine_name="")` sends none. A name set later with `rename_machine`
is kept on re-activation.

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
from latte import MASTER_PUBLIC_KEYS, check_license, CertChain, VerifyError, ValidateError

chain = CertChain(submaster=..., project=..., daily=...)

try:
    lic = check_license(MASTER_PUBLIC_KEYS, token, chain, sdk.machine_id)
    print("license OK, expires", lic.expires_at)
    if lic.in_grace_period:
        print("warning: offline a while, please reconnect soon")
except VerifyError as e:
    print("could not verify license:", e)  # chain/signature/format problem
except ValidateError as e:
    print("license rejected:", e)  # verified fine, but expired/out of grace/wrong machine
```

`machine_id` here is the derived ID, never a raw one: pass `sdk.machine_id`,
or `latte.machineid.protected_id(raw, app_id)` if you have no `Sdk`.

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

`expires_at` is 2099-01-01T00:00:00Z (`4070908800`) for a licence that never ends.

The activation token comes in two formats, told apart by whether it carries
a `grc` claim:

- **With `grc`:** `exp` is the licence's end (`expires_at`) and the grace
  period is `grc` seconds.
- **Without `grc`:** `exp` is the offline deadline itself, so the grace
  period is `exp - iat`, and the optional `lex` claim (unix seconds) is the
  licence's end. No `lex` means `expires_at` is 2099-01-01T00:00:00Z. Past `lex` the
  token raises `HardExpiredError` even when `exp` is later.

Both read into the same `issued_at`/`expires_at`/`grace_period_secs`, so the
rules above apply unchanged. The token's `exp` is never enforced while
verifying the signature chain; it is enforced only here, as these two
errors.

`PublicLicense.in_grace_period` is a softer, earlier warning signal: it
turns `True` once more than 60 minutes have passed since the last
issuance/renewal without a fresh one arriving, while still inside the grace
window: surface it as a "please reconnect soon" hint, distinct from an
outright rejection.

## Entitlements

Entitlements are the typed answers a seller signed into a licence about what
their customer bought. Two questions, and only two: *may this customer do X*
(a boolean) and *how many Y do they get* (an integer).

```python
lic = sdk.activate(key)

if lic.can("export_pdf"):
    enable_pdf_export()

max_projects = lic.limit("max_projects")
if max_projects is not None and max_projects != latte.UNLIMITED and used >= max_projects:
    raise ProjectLimitReached
```

You set the values on a policy and override them per licence in the
dashboard; the server resolves the two and signs the result into the
activation token, so `can` and `limit` answer offline with no network call.

`latte.UNLIMITED` is `-1`. `limit` returns it as-is — compare against the
constant rather than testing for a negative number.

### The rules

| | |
|---|---|
| **Absence denies.** | An unset key is ``can() is False``, ``limit() is None``. |
| **No coercion.** | `can` on an integer is false even when it is non-zero. `limit` on a boolean misses rather than returning 1 or 0. |
| **Keys are byte-exact.** | No case folding, no trimming. |
| **A bad value is dropped, never fatal.** | If a value reaches the token that is neither a boolean nor an integer, that one entry vanishes and the licence stays valid. |

### Rolling this out without switching your own features off

Absence denies, and that has a consequence worth reading twice: **a token
issued before you set any entitlements answers `False` to everything.** Ship
`if not lic.can("export_pdf"): hide()` and every customer still holding a
cached token from before the change loses PDF export until they renew.

`has_entitlements` exists for exactly this, and it is not a convenience
accessor:

```python
enabled = lic.can("export_pdf") if lic.has_entitlements else legacy_behaviour()
```

The published order is: set the values in the dashboard first, wait one
grace window for the installed base to renew, then ship the release that
reads them behind `has_entitlements`, and drop the fallback once the base
has turned over.

`has_entitlements` reports whether the claim was **present**, including when
it is empty — which is why it is not a `len(lic.entitlements)` check.

### Entitlements are not metadata

Entitlements and `metadata` are separate namespaces and never merge.
Metadata is arbitrary display data, filtered per field in the dashboard, and
untyped; entitlements are booleans and integers, unfiltered, and exist
precisely to be read on the customer's machine. The same key may appear in
both meaning different things.

Entitlements are a distribution mechanism for a signed answer, not a
tamper-proofing one — see the threat-model section above. Entitlements
change nothing about it. If real revenue depends on a feature, re-validate
it server-side.

---

## What this package does *not* do

Background renewal scheduling is intentionally out of scope. There's no
scheduler here: `Sdk.renew` is the building block; call it on a timer, in
response to a UI action, or whatever fits your application.

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
