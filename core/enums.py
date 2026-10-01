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


class Scanner(str, Enum):
    interceptor = "interceptor"
    tracer = "tracer"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
