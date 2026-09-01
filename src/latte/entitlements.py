"""Typed entitlements: the answers a seller signed into a licence about
what their customer bought.

An entitlement answers one of exactly two questions about the software you
shipped: *may this customer do X* (a boolean, read with ``can``) and *how
many Y do they get* (an integer, read with ``limit``). The values are set
on a policy and overridden per licence in the LicenseLatte dashboard,
resolved server-side, and signed into the activation token as the ``ent``
claim -- so ``can`` and ``limit`` answer fully offline, with no network
call and no second source of truth.

They are deliberately not the same thing as ``metadata`` (the ``pmd``
claim): metadata is arbitrary display data, filtered per field, and
untyped. Entitlements are booleans and integers, unfiltered, and exist
precisely to be read on the customer's machine. The two never merge, and
the same key may appear in both meaning different things.

Absence denies, and that has a rollout consequence
--------------------------------------------------

A key that is not in the claim answers ``False`` / ``None``. There is no
"unknown means allow": the token is a bearer artefact sitting in a file on
the machine of the person it constrains, so if absence granted, stripping
the claim would unlock everything, and replaying a token minted before the
seller adopted entitlements would do the same with no tampering at all.

The cost of that default lands on you, not on the server. Shipping::

    if not lic.can("export_pdf"):
        hide()

before your installed base has renewed disables PDF export for every
customer whose cached token predates the claim. Use ``has_entitlements``
to bridge one release::

    enabled = lic.can("export_pdf") if lic.has_entitlements else legacy()

Drop the fallback once the base has renewed -- one grace window, which the
dashboard shows per policy.

Tamper resistance
-----------------

Entitlements are a distribution mechanism for a signed answer, not a
tamper-proofing one. Python bytecode is trivially readable and patchable
(see the Threat Model section of README.md), and entitlements change
nothing about that. If real revenue depends on a feature, re-validate it
server-side.
"""

from __future__ import annotations

import math
from typing import Mapping, Union

#: An entitlement value: a boolean, or an integer.
#:
#: Two types and no more. Strings would be the untyped bag with extra
#: steps, enums are N booleans with a schema the client has to know, and
#: floats round-trip through five JSON parsers with five opinions about
#: ``1.0`` versus ``1``.
EntitlementValue = Union[bool, int]

#: The sentinel an integer entitlement carries to mean "no ceiling".
#: ``limit()`` returns it as-is; compare against this constant rather than
#: testing for a negative number::
#:
#:     n = lic.limit("max_projects")
#:     if n is not None and n != latte.UNLIMITED and used >= n:
#:         raise TooManyProjects
UNLIMITED = -1


def decode_entitlements(
    claims: Mapping[str, object],
) -> dict[str, EntitlementValue] | None:
    """Narrow a raw ``ent`` claim to the two types the format admits,
    dropping everything else.

    Dropping rather than raising is the contract, not laxity: rejecting a
    token because a seller managed to get a string into one value would
    take a working product offline for a data-entry mistake, on a machine
    that cannot be reached to fix it. Refusing bad values is the server's
    job at write time, where there is a human and an error message.

    ``bool`` is checked before ``int`` deliberately -- in Python ``bool``
    *is* an ``int`` subclass, so testing ``isinstance(v, int)`` first would
    classify every boolean entitlement as an integer and hand ``limit()``
    a 1 or a 0, which is exactly the coercion the cross-SDK contract
    forbids.

    A whole-valued float is an integer (``25.0`` is 25) while a fractional
    one is dropped: Go's and JavaScript's JSON parsers hand back a float
    for both, so a rule that distinguished them is one two of the five SDKs
    could not implement.

    Returns ``None`` when the claim is absent, which is a different thing
    from an empty mapping -- ``has_entitlements`` reads exactly that
    distinction.
    """
    raw = claims.get("ent")
    if not isinstance(raw, dict):
        return None

    out: dict[str, EntitlementValue] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, int):
            out[key] = value
        elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
            out[key] = int(value)
    return out


def can(entitlements: Mapping[str, EntitlementValue], key: str) -> bool:
    """Whether the boolean entitlement named by ``key`` is present and true.

    A key that is absent, or that holds an integer rather than a boolean,
    answers ``False``. There is no coercion across kinds: ``can`` on an
    integer entitlement is false even when that integer is non-zero,
    because a rule that read "nonzero is true" is one five SDKs would
    eventually disagree about.
    """
    value = entitlements.get(key)
    return value is True


def limit(entitlements: Mapping[str, EntitlementValue], key: str) -> int | None:
    """The integer entitlement named by ``key``, or ``None`` when absent.

    The unlimited sentinel is returned as-is: compare the result against
    :data:`UNLIMITED` rather than testing for a negative number. A key that
    holds a boolean rather than an integer misses -- ``limit`` on a boolean
    is ``None``, not 1 or 0.
    """
    value = entitlements.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
