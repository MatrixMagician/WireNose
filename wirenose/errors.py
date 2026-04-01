"""Custom exceptions for the WireNose capture engine."""


class CapturePermissionError(PermissionError):
    """Raised when packet capture requires elevated privileges.

    Wraps the underlying PermissionError from Scapy/libpcap with a
    user-friendly message suggesting sudo.
    """

    def __init__(self, interface: str, original: PermissionError | None = None) -> None:
        self.interface = interface
        self.original = original
        msg = (
            f"Permission denied capturing on '{interface}'. "
            f"Run with sudo: sudo wirenose capture -i {interface}"
        )
        super().__init__(msg)


class InvalidFilterError(ValueError):
    """Raised when a BPF filter expression is syntactically invalid.

    Wraps Scapy_Exception from libpcap's filter compilation.
    """

    def __init__(self, bpf_filter: str, original: Exception | None = None) -> None:
        self.bpf_filter = bpf_filter
        self.original = original
        msg = f"Invalid BPF filter: '{bpf_filter}'"
        if original:
            msg += f" — {original}"
        super().__init__(msg)
