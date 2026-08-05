"""Provider-neutral realization of in-band infrastructure authority."""

from .authority import (
    CapabilityReconciler,
    InstalledCapability,
    MAX_SERVICE_GRANTS,
    ReconcileResult,
    ServiceGrant,
    authorize_service,
)


__all__ = (
    "CapabilityReconciler",
    "InstalledCapability",
    "MAX_SERVICE_GRANTS",
    "ReconcileResult",
    "ServiceGrant",
    "authorize_service",
)
