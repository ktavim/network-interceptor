from enum import Enum


class AuthMethod(str, Enum):
    """The combined vocabulary of both scanners. The interceptor never emits
    login_redirect or dns_failed, and the tracer never emits kerberos or
    api_key; every other value can come from either."""
    ntlm = "ntlm"
    kerberos = "kerberos"
    negotiate = "negotiate"
    oauth = "oauth"
    login_redirect = "login_redirect"
    basic = "basic"
    bearer = "bearer"
    api_key = "api_key"
    other = "other"
    unauthenticated = "unauthenticated"
    no_response = "no_response"
    dns_failed = "dns_failed"
    unknown = "unknown"


class Severity(str, Enum):
    blocker = "blocker"
    review = "review"
    cleared = "cleared"
    # Already published through the F5, by a workaround the scanners cannot
    # see. Set only from the published-origins registry, in
    # core.jobs._recompute_services, whatever the auth method says;
    # translate.severity_for never returns it. Where cleared means the F5 can
    # publish the origin and someone still has to, published means nothing
    # is left to configure.
    published = "published"


class ScanStatus(str, Enum):
    """Derived from the scan's jobs (core.jobs.scan_status)."""
    queued = "queued"
    running = "running"
    completed = "completed"
    # At least one of the scan's jobs completed and the rest failed.
    partial = "partial"
    failed = "failed"
    cancelled = "cancelled"


class Scanner(str, Enum):
    interceptor = "interceptor"
    tracer = "tracer"


class SourceKind(str, Enum):
    """Where a scanner found a service's origin (api.models.Source). The first
    five are the tracer's provenance kinds, the prefix of each string in
    urls.sources; page is the interceptor's, a urls.page_url."""
    # A config the page loaded, a JS bundle it loaded, or an element of the
    # page, that named a URL of the origin.
    network = "network"
    js = "js"
    dom = "dom"
    # A probed URL whose redirect pointed at the origin.
    redirect = "redirect"
    # The origin's root, which the tracer probed on its own initiative after
    # the URL named here answered 4xx.
    synthesized = "synthesized"
    # A page the interceptor's browser was on when it called the origin.
    page = "page"


class ExposureStatus(str, Enum):
    """Where an exposure is in publishing its app through the F5
    (docs/exposure-design.md, Lifecycle). Not the app's exposure_state, which
    says how far the app's scans have got toward a submission."""
    # The admin is arranging the services into VIPs.
    grouping = "grouping"
    # Waiting for the agent to reserve IPs, render AS3 and dry-run it.
    planning = "planning"
    awaiting_confirmation = "awaiting_confirmation"
    # Waiting for the agent to deploy, verify and create DNS records.
    deploying = "deploying"
    deployed = "deployed"
    failed = "failed"
    # Waiting for the agent to release what the exposure holds.
    cancelling = "cancelling"
    cancelled = "cancelled"
    # A newer submission of the app replaced it before it deployed.
    superseded = "superseded"


# The statuses no exposure leaves: the history. Every other one is open.
CLOSED_EXPOSURE_STATUSES = (
    ExposureStatus.deployed,
    ExposureStatus.cancelled,
    ExposureStatus.superseded,
)


# The statuses an exposure can be in alongside another of its app's: the
# closed ones; deploying, which cannot be stopped, so a new submission leaves
# it to finish; and cancelling, which is winding down already. Of the rest,
# the exposures a new submission supersedes, an app has at most one.
NON_EXCLUSIVE_EXPOSURE_STATUSES = (
    *CLOSED_EXPOSURE_STATUSES,
    ExposureStatus.deploying,
    ExposureStatus.cancelling,
)


class ExposurePhase(str, Enum):
    """What the agent is doing for an exposure: the status it works in, and
    the phase a result or a failure belongs to."""
    planning = "planning"
    deploying = "deploying"
    cancelling = "cancelling"


class ExposureScope(str, Enum):
    """What an exposure does with one of its scan's services."""
    # Cleared and not yet published: the exposure gives it a VIP.
    needs_vip = "needs_vip"
    # Already on the F5. No VIP, but the app's rewrite map needs its URL.
    published = "published"
    # Excluded on the scan; out of scope.
    excluded = "excluded"
    # Published on the scan, but its registry entry has since been removed and
    # its auth method does not clear: it blocks planning until it is
    # registered again, or the app is rescanned and resubmitted.
    unresolved = "unresolved"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
