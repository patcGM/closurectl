"""Typed errors that are safe to show to CLI users."""


class ClosureCtlError(Exception):
    """Base class for expected closurectl failures."""


class ValidationError(ClosureCtlError):
    """Input does not satisfy the declared schema or safety constraints."""


class PlanningError(ClosureCtlError):
    """A closure plan could not be produced."""


class AdapterError(ClosureCtlError):
    """A read-only provider inventory operation failed."""


class SignatureError(ClosureCtlError):
    """A receipt signature or digest is invalid."""
