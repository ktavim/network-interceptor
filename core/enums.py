from enum import Enum


class AuthMethod(str, Enum):
    ntlm = "ntlm"
    kerberos = "kerberos"
    negotiate = "negotiate"
    oauth = "oauth"
    basic = "basic"
    bearer = "bearer"
    api_key = "api_key"
    mtls = "mtls"
    other = "other"
    unauthenticated = "unauthenticated"
    no_response = "no_response"
    unknown = "unknown"


class Severity(str, Enum):
    blocker = "blocker"
    review = "review"
    cleared = "cleared"
