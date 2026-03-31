from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from windows_catalog import WindowsSoftwareCatalog
from windows_catalog_models import BackendContext, DeployOptions, DetectionResult
from windows_deploy_engine import WindowsDeployEngine
from windows_execution_backends import LocalSubprocessBackend, PsExecBackend, WindowsExecutionBackend


@dataclass(slots=True)
class WindowsDeployRuntime:
    backend_name: str
    target_host: str
    timeout_sec: int
    skip_if_detected: bool
    skip_pre_detection: bool
    prefer_system_context: bool
    psexec_path: str


class WindowsDeployService:
    def __init__(self, catalog_path: str, logger: Callable[[str], None] | None = None):
        self.catalog_path = catalog_path
        self.logger = logger or (lambda _msg: None)

    def _build_backend(self, runtime: WindowsDeployRuntime) -> WindowsExecutionBackend:
        if runtime.backend_name == "psexec":
            return PsExecBackend(runtime.psexec_path, logger=self.logger)
        return LocalSubprocessBackend(logger=self.logger)

    def check_package(self, package_id: str, runtime: WindowsDeployRuntime) -> tuple[DetectionResult, str]:
        catalog = WindowsSoftwareCatalog.load(self.catalog_path)
        package = catalog.get(package_id)
        backend = self._build_backend(runtime)
        context = BackendContext(
            target_host=runtime.target_host,
            timeout_sec=max(30, int(runtime.timeout_sec or package.timeout_sec)),
            requires_admin=package.requires_admin,
            prefer_system_context=runtime.prefer_system_context,
        )
        backend.validate_context(context)
        detection = backend.run_detection(package, context)
        return detection, backend.name

    def install_package(self, package_id: str, force_reinstall: bool, runtime: WindowsDeployRuntime):
        catalog = WindowsSoftwareCatalog.load(self.catalog_path)
        package = catalog.get(package_id)
        backend = self._build_backend(runtime)
        engine = WindowsDeployEngine(backend=backend, logger=self.logger)
        options = DeployOptions(
            timeout_sec=max(30, int(runtime.timeout_sec or package.timeout_sec)),
            skip_if_detected=(not force_reinstall) and runtime.skip_if_detected,
            skip_pre_detection=runtime.skip_pre_detection,
            prefer_system_context=runtime.prefer_system_context,
        )
        return engine.deploy(package=package, target_host=runtime.target_host, options=options)
