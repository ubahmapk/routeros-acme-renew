class RenewError(RuntimeError):
    """A step failed in a way the operator needs to hear about."""


class NoCertificateError(RenewError):
    """The TLS handshake did not produce a certificate.

    RouterOS `www-ssl` with no certificate assigned only offers anonymous ciphers, which a modern client
    rejects, so this is how "the router has no certificate yet" shows up.
    """
