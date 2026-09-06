"""What each methodology class YIELDS, and what it REQUIRES — the chain substrate.

A chain planner without this table is a story generator: it can only compose on
titles, and "SQL injection here, weak session there, therefore account takeover"
is a sentence, not a hypothesis. What makes composition *falsifiable* is naming,
per class, the artifact its confirmation actually puts in our hands and the
artifact it can consume.

Two rules keep the table honest, and both are enforced by
:mod:`tests.test_chaining.test_vocabulary`:

**Every dispatchable class is accounted for.** A class either declares a yield or
appears in :data:`NO_YIELD_REASON` with a substantive sentence. A class silently
absent would be invisible to chaining forever, which is exactly the
silent-degradation shape the contribution ledger exists to catch.

**A yield is what the confirmation PROVES, never what the class is named after.**
Reflected XSS is *about* stealing a session, and this engine has never
demonstrated exfiltrating one — its P7 oracle witnesses script execution, which
is not a token in our hands. So it declares no yield and says why. Declaring the
aspiration would make every XSS finding the first link of a chain whose second
link could never be carried, and a chain that cannot be carried cannot be
falsified.
"""

from __future__ import annotations

from enum import StrEnum


class ArtifactKind(StrEnum):
    """A thing a confirmed step can put in our hands, or need in order to fire.

    Deliberately coarse. The kind is a *routing* label — it decides which step
    can feed which — while the acceptance oracle that proves a carriage lives in
    :mod:`~clinkz.chaining.composition`. A finer taxonomy would multiply the
    routing table without making a single composition more provable.

    Attributes:
        CREDENTIAL: A username/password pair recovered from somewhere it should
            not have been readable.
        SESSION_TOKEN: A session identifier, bearer token or signed cookie that
            an authenticated request would carry.
        SIGNING_KEY: Key material a token is signed or encrypted with.
        IDENTITY: A principal identifier (account id, email, username) belonging
            to somebody other than the tester.
        FILE_PATH: A server-side filesystem path the application resolves.
        FILE_CONTENT: Bytes read off the server's filesystem.
        COMMAND_OUTPUT: Output produced by a command the server executed.
        DB_RECORD: Rows read out of the application's database.
        INTERNAL_ENDPOINT: A URL reachable from the server but not from us.
        INTERNAL_RESPONSE: Content the server fetched from such a URL.
        STORED_ARTIFACT: A file we uploaded that the application will serve or
            consume.
        ADMIN_CAPABILITY: A privilege the application grants us that it did not
            intend to.
    """

    CREDENTIAL = "credential"
    SESSION_TOKEN = "session_token"
    SIGNING_KEY = "signing_key"
    IDENTITY = "identity"
    FILE_PATH = "file_path"
    FILE_CONTENT = "file_content"
    COMMAND_OUTPUT = "command_output"
    DB_RECORD = "db_record"
    INTERNAL_ENDPOINT = "internal_endpoint"
    INTERNAL_RESPONSE = "internal_response"
    STORED_ARTIFACT = "stored_artifact"
    ADMIN_CAPABILITY = "admin_capability"


_A = ArtifactKind

#: What a CONFIRMED finding of each class puts in our hands.
#:
#: Read strictly: the entry names what the class's own defining effect
#: demonstrates, not what the vulnerability is famous for enabling. ``_test_sqli``
#: yields ``DB_RECORD`` because a UNION data row in a successful response IS rows
#: out of the database; it does not yield ``CREDENTIAL``, because whether those
#: rows contained credentials is a question about the bytes, answered by
#: :func:`~clinkz.chaining.composition.credentials_in` at plan time rather than
#: assumed here.
CLASS_YIELDS: dict[str, tuple[ArtifactKind, ...]] = {
    "_test_sqli": (_A.DB_RECORD,),
    "_test_nosqli": (_A.DB_RECORD,),
    "_test_lfi": (_A.FILE_CONTENT,),
    "_test_xxe": (_A.FILE_CONTENT,),
    "_test_cmdi": (_A.COMMAND_OUTPUT,),
    "_test_ssrf": (_A.INTERNAL_RESPONSE,),
    "_test_log4shell": (_A.INTERNAL_RESPONSE,),
    "_test_file_upload": (_A.STORED_ARTIFACT,),
    "_test_secrets_exposure": (_A.CREDENTIAL, _A.SIGNING_KEY, _A.INTERNAL_ENDPOINT),
    "_test_brute_force": (_A.CREDENTIAL,),
    "_test_weak_session": (_A.SESSION_TOKEN,),
    "_test_crypto": (_A.SESSION_TOKEN, _A.SIGNING_KEY),
    "_test_jwt": (_A.SESSION_TOKEN,),
    "_test_idor": (_A.DB_RECORD, _A.IDENTITY),
    "_test_mass_assignment": (_A.ADMIN_CAPABILITY,),
}

#: What a class can CONSUME — an artifact that lets it reach further than it
#: could unaided. Consuming is optional everywhere: no class is gated on an
#: artifact, so a chain never suppresses the single-service test.
CLASS_REQUIRES: dict[str, tuple[ArtifactKind, ...]] = {
    # A recovered path is a traversal target the parameter fuzz would not guess.
    "_test_lfi": (_A.FILE_PATH,),
    # An internal URL learned elsewhere is a fetch target worth pointing at.
    "_test_ssrf": (_A.INTERNAL_ENDPOINT,),
    # Key material turns "the token is decodable" into "the token is forgeable".
    "_test_jwt": (_A.SIGNING_KEY,),
    "_test_crypto": (_A.SIGNING_KEY,),
    # A second principal is what makes an authorization boundary measurable at
    # all — the class's own stated limitation.
    "_test_idor": (_A.CREDENTIAL, _A.SESSION_TOKEN, _A.IDENTITY),
    "_test_mass_assignment": (_A.CREDENTIAL, _A.SESSION_TOKEN),
    # A second identity is what makes a crossing measurable at all — it is the
    # class's own stated limitation, and the reference the payload carries has to
    # be discovered by probing as that identity.
    "_test_write_crossing": (_A.CREDENTIAL, _A.SESSION_TOKEN, _A.IDENTITY),
    "_test_state_sequence": (_A.CREDENTIAL, _A.SESSION_TOKEN),
    "_test_constraint_violation": (_A.CREDENTIAL, _A.SESSION_TOKEN),
    "_test_repeatability": (_A.CREDENTIAL, _A.SESSION_TOKEN),
}

#: Classes that yield nothing, and WHY — the other half of the accounting.
#:
#: Each sentence has to survive review, because "no yield" is a coverage claim: a
#: class here can never begin a chain, and if the reason is wrong the engine has
#: silently declined to escalate a real one.
NO_YIELD_REASON: dict[str, str] = {
    "_test_write_crossing": (
        "The confirmed effect is an object WE wrote, attributed to another principal. "
        "Nothing came back: the value the object carries is the owner reference this "
        "engine put there, and the reference itself was discovered by probing as a "
        "principal whose session the engagement already held. Declaring IDENTITY here "
        "would make every crossing the head of a chain built on a credential we were "
        "GIVEN, which is the reflected-XSS mistake — a yield is what a class's "
        "confirmation PROVES, not what it is named after."
    ),
    "_test_xss_reflected": (
        "The confirmed effect is a payload landing in an executable context, and "
        "under P7 a script executing. Neither is a token in our hands: this engine "
        "never exfiltrates a session, so declaring SESSION_TOKEN here would make "
        "every XSS finding the head of a chain whose next link cannot be carried."
    ),
    "_test_xss_stored": (
        "Same as reflected XSS — execution witnessed, nothing recovered. The "
        "stored-payload persistence is a property of the record, not an artifact "
        "the engine holds."
    ),
    "_test_xss_dom": (
        "Same again, and the effect lives entirely in the browser: the P7 witness "
        "is a nonce Clinkz minted and injected itself, so what returns is our own "
        "value. Execution is proven and nothing is recovered — the page's own "
        "session is never read out, and a token the engine did not obtain cannot "
        "be carried anywhere."
    ),
    "_test_csrf": (
        "The confirmation is token-absence and origin-acceptance analysis. Nothing "
        "is recovered, and the proving action — actually performing the "
        "state change as another origin — is what the rails refuse."
    ),
    "_test_open_redirect": (
        "The confirmed effect is a 3xx Location navigating off-site. A token that "
        "rode the redirect would be an artifact, but this engine never observes "
        "the victim's request, so nothing is recovered."
    ),
    "_test_ssti": (
        "The confirmed effect is a rendered arithmetic product or an RCE canary in "
        "output position. The canary is our own value returning; the class's "
        "escalation to command execution is _test_cmdi's territory, which declares "
        "COMMAND_OUTPUT itself."
    ),
    "_test_security_headers": (
        "A posture assessment of the response's own headers. It recovers nothing "
        "and grants nothing — it describes the response it read."
    ),
    "_test_prototype_pollution": (
        "The confirmed effect is a key this engine wrote onto the target process's "
        "Object.prototype, witnessed coming back as a response header or a status "
        "code on a later request. That is a write we made, not an artifact we "
        "recovered: what returns is our own minted value. The class is *about* "
        "escalating to command execution through a gadget chain, and this engine "
        "demonstrates no gadget — declaring COMMAND_OUTPUT would make every "
        "pollution finding the head of a chain whose next link cannot be carried, "
        "which is the reflected-XSS mistake in a different costume."
    ),
    "_test_csp": (
        "Whether a served policy leaves script reachable is a property of the "
        "policy. Even a confirmed bypass hands back a witnessed execution, not an "
        "artifact — the same limit as the XSS classes."
    ),
    "_test_javascript_attacks": (
        "The confirmed effect is the server accepting a value rebuilt from the "
        "page's own client-side chain. The rebuilt value is ours, not the "
        "application's, so nothing was recovered from it."
    ),
    "_test_input_validation": (
        "The confirmed effect is the server accepting a value it declares invalid. "
        "Acceptance of our own value recovers nothing."
    ),
    "_test_state_sequence": (
        "The confirmed effect is a terminal state reached out of sequence. The "
        "resource is left in a state the application owns; no artifact crosses "
        "back to us, so this class can only ever be a chain's LAST link."
    ),
    "_test_constraint_violation": (
        "The confirmed effect is a persisted record carrying a value the "
        "application's own surface forbids. Like the sequence class it changes "
        "the application's state rather than handing us anything."
    ),
    "_test_repeatability": (
        "The confirmed effect is a single-use action applied a second time. The "
        "cumulative effect is observed on the application's own record, not "
        "recovered."
    ),
    "_test_tier2_technique": (
        "A research-runbook technique whose result shape is not known in advance. "
        "Declaring a yield would be declaring one for whatever the runbook "
        "happened to say, which is not a contract this table can keep."
    ),
    "_test_tier3_technique": (
        "As tier 2, and more so: an experimental technique read from live research "
        "has no declared result shape at all, so any yield claimed for it would be "
        "a claim about whatever text the runbook happened to contain on the day."
    ),
}


#: Which of P1–P7 each class's confirmation reduces to.
#:
#: A chain emits only when EVERY link is independently confirmed by a P1–P7
#: oracle, so each link has to be able to name the one that proved it. A
#: confirmed finding does not carry that name today (only a discovery-originated
#: one does, on its provenance), and inventing it per link would make the rule
#: self-certifying. So it is declared here, per class, from what the class's
#: methodology actually observes — and a class may legitimately reduce to more
#: than one, which is why the value is a tuple rather than a string.
#:
#: The chaining CARRIAGE link is **P4** — "forged input accepted exactly as a
#: valid baseline while a broken control is rejected". That is precisely the
#: decoy-substitution oracle, which means chaining introduces no new confirmation
#: primitive and inherits the existing zero-FP boundary rather than widening it.
CLASS_CONFIRMATION_PRIMITIVES: dict[str, tuple[str, ...]] = {
    "_test_sqli": ("P1", "P2", "P3"),
    "_test_nosqli": ("P1", "P5"),
    "_test_ssti": ("P1", "P2"),
    "_test_xxe": ("P3", "P5"),
    "_test_jwt": ("P4",),
    "_test_ssrf": ("P1", "P3", "P4", "P6"),
    "_test_log4shell": ("P6",),
    "_test_xss_reflected": ("P2",),
    "_test_xss_stored": ("P2",),
    "_test_xss_dom": ("P7",),
    "_test_cmdi": ("P2",),
    "_test_lfi": ("P3",),
    "_test_file_upload": ("P2", "P3"),
    "_test_csrf": ("P1",),
    "_test_idor": ("P1", "P4"),
    "_test_brute_force": ("P1", "P4"),
    "_test_open_redirect": ("P1",),
    "_test_security_headers": ("P1",),
    "_test_weak_session": ("P1", "P5"),
    "_test_javascript_attacks": ("P4",),
    "_test_csp": ("P7",),
    "_test_crypto": ("P3", "P4"),
    "_test_input_validation": ("P4",),
    "_test_secrets_exposure": ("P3",),
    "_test_mass_assignment": ("P4",),
    # The persisted object is read back and compared against a never-issued
    # owner reference that round-trips identically — the decoy-substitution
    # oracle, on a record instead of a response.
    "_test_write_crossing": ("P4",),
    "_test_state_sequence": ("P4",),
    "_test_constraint_violation": ("P4",),
    "_test_repeatability": ("P4",),
    # A runbook technique's own methodology states its verification; the chain
    # gate refuses a link that cannot name a primitive, so a tier-2/3 step cannot
    # silently become a confirmed link.
    "_test_tier2_technique": (),
    "_test_tier3_technique": (),
}


def confirmation_primitives_of(test_method: str) -> str:
    """The P-primitive label for a link of class *test_method*.

    Returns:
        A ``/``-joined label (``"P1/P2/P3"``), or ``""`` when the class declares
        none — which makes the link fail the chain gate, deliberately.
    """
    return "/".join(CLASS_CONFIRMATION_PRIMITIVES.get(test_method, ()))


def yields_of(test_method: str) -> tuple[ArtifactKind, ...]:
    """Artifact kinds a confirmed *test_method* finding puts in our hands."""
    return CLASS_YIELDS.get(test_method, ())


def requires_of(test_method: str) -> tuple[ArtifactKind, ...]:
    """Artifact kinds *test_method* can consume to reach further."""
    return CLASS_REQUIRES.get(test_method, ())


def can_follow(producer: str, consumer: str) -> tuple[ArtifactKind, ...]:
    """Artifact kinds that *producer* yields and *consumer* can consume.

    Args:
        producer: The earlier step's ``_test_*`` method.
        consumer: The later step's ``_test_*`` method.

    Returns:
        The intersection, in :class:`ArtifactKind` declaration order so two runs
        compose the same chain — never in dict-iteration or discovery order.
    """
    produced = set(yields_of(producer))
    consumed = set(requires_of(consumer))
    both = produced & consumed
    return tuple(kind for kind in ArtifactKind if kind in both)


__all__ = [
    "CLASS_CONFIRMATION_PRIMITIVES",
    "CLASS_REQUIRES",
    "CLASS_YIELDS",
    "NO_YIELD_REASON",
    "ArtifactKind",
    "can_follow",
    "confirmation_primitives_of",
    "requires_of",
    "yields_of",
]
