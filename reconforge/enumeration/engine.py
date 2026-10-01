"""Deterministic orchestration for passive service enumeration."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..core.models import EnumerationDecision, EnumerationEvidence, EnumerationStatus, EnumerationTarget
from .modules import HttpEnumerationModule, SshEnumerationModule, TlsEnumerationModule


@dataclass(frozen=True)
class _ModuleRegistration:
    name: str
    priority: str
    module: object


class EnumerationEngine:
    """Route supported services to safe, protocol-specific enumeration modules."""

    def __init__(self, modules: Sequence[object] | None = None) -> None:
        defaults = modules or (HttpEnumerationModule(), SshEnumerationModule(), TlsEnumerationModule())
        self.modules = tuple(defaults)

    def decide(self, target: EnumerationTarget) -> EnumerationDecision:
        candidates = [module for module in self.modules if getattr(module, "supports", lambda _target: False)(target)]
        if not candidates:
            service_hint = target.service_name or target.product or f"port {target.port}"
            return EnumerationDecision(
                target=target,
                module=None,
                reason=f"no supported module for {service_hint}",
                priority="normal",
                status=EnumerationStatus.UNSUPPORTED,
                evidence=(
                    EnumerationEvidence(
                        source="service_match",
                        category="service",
                        indicator="service_name",
                        value=str(service_hint).strip()[:256],
                        confidence="low",
                        details="No module was selected because the service metadata did not match a supported enumeration rule.",
                    ),
                ),
            )

        module = candidates[0]
        name = getattr(module, "name", module.__class__.__name__)
        reason = self._reason(target, name)
        return EnumerationDecision(
            target=target,
            module=name,
            reason=reason,
            priority=getattr(module, "priority", "normal"),
            status=EnumerationStatus.SUCCESS,
            evidence=(),
        )

    def run(self, target: EnumerationTarget) -> EnumerationDecision:
        decision = self.decide(target)
        if decision.module is None or decision.status is EnumerationStatus.UNSUPPORTED:
            return decision
        module = next(module for module in self.modules if getattr(module, "name", None) == decision.module)
        result = module.enumerate(target)
        decision = EnumerationDecision(
            target=target,
            module=decision.module,
            reason=decision.reason,
            priority=decision.priority,
            status=result.status,
            evidence=result.evidence,
        )
        return decision

    @staticmethod
    def _reason(target: EnumerationTarget, module_name: str) -> str:
        identifiers = [
            value for value in (target.service_name, target.product, target.version, target.extra_info) if value and str(value).strip()
        ]
        suffix = ", ".join(str(value) for value in identifiers[:3]) if identifiers else f"port {target.port}/{target.protocol}"
        return f"{module_name} selected from service evidence: {suffix}"

    def supported_modules(self) -> tuple[str, ...]:
        return tuple(getattr(module, "name", module.__class__.__name__) for module in self.modules)
