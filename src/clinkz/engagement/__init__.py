"""Engagement setup — what a real engagement needs before anything is sent.

  * :mod:`clinkz.engagement.gate` — the refusals (no authorization record, or
    outside the authorized window). Dependency-free so the safety governor can
    import it.
  * :mod:`clinkz.engagement.credential_shapes` — what credential material LOOKS
    like; the one vocabulary shared by the redactor and the disclosure gate.
  * :mod:`clinkz.engagement.secrets` — credential intake and the process-wide
    redaction registry (values AND shapes).
  * :mod:`clinkz.engagement.artifact_scan` — the disclosure gate: reads the
    written bundle back off disk and refuses to call it clean on the strength
    of the same logic that produced it.
  * :mod:`clinkz.engagement.auth_state` — authentication-mechanism detection,
    the authenticated-state assertion, and session maintenance.
  * :mod:`clinkz.engagement.dryrun` — enumerate what the engagement WOULD do,
    without sending anything.

Import order below is deliberate: ``gate`` first, because ``dryrun`` reaches
into :mod:`clinkz.safety`, which imports ``gate`` back.
"""

from clinkz.engagement.artifact_scan import (
    ArtifactFinding,
    ArtifactScanReport,
    run_disclosure_gate,
    scan_artifact_tree,
)
from clinkz.engagement.credential_shapes import (
    find_shapes,
    fingerprint_jwt,
    redact_shapes,
)
from clinkz.engagement.gate import (
    AuthorizationRequiredError,
    EngagementAbortedError,
    EngagementWindowClosedError,
    open_engagement,
    require_authorization,
    require_window_open,
)
from clinkz.engagement.secrets import (
    CredentialFileError,
    clear_secrets,
    load_credential_file,
    prompt_for_credentials,
    redact,
    redact_structure,
    register_secret,
)

from clinkz.engagement.auth_state import (  # isort: skip — must follow gate/secrets
    PROTECTED_PATH_CANDIDATES,
    AuthAssertion,
    AuthMechanism,
    AuthStateError,
    assert_authenticated,
    detect_auth_mechanism,
)
from clinkz.engagement.dryrun import DryRunPlan, build_dry_run_plan, render_dry_run

__all__ = [
    "PROTECTED_PATH_CANDIDATES",
    "ArtifactFinding",
    "ArtifactScanReport",
    "AuthAssertion",
    "AuthMechanism",
    "AuthStateError",
    "AuthorizationRequiredError",
    "CredentialFileError",
    "DryRunPlan",
    "EngagementAbortedError",
    "EngagementWindowClosedError",
    "assert_authenticated",
    "build_dry_run_plan",
    "clear_secrets",
    "detect_auth_mechanism",
    "find_shapes",
    "fingerprint_jwt",
    "load_credential_file",
    "open_engagement",
    "prompt_for_credentials",
    "redact",
    "redact_shapes",
    "redact_structure",
    "register_secret",
    "render_dry_run",
    "require_authorization",
    "require_window_open",
    "run_disclosure_gate",
    "scan_artifact_tree",
]
