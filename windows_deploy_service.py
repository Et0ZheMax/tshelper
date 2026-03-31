from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from windows_catalog import WindowsSoftwareCatalog
from windows_catalog_models import BackendContext, DeployOptions, DetectionResult, WindowsExecutionMode
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
    execution_mode: WindowsExecutionMode = WindowsExecutionMode.STANDARD_INSTALL
    remote_temp_dir: str = "C:\\Windows\\Temp\\tshelper_deploy"
    delivery_folder: str = "C:\\Installers\\TSHelper"


class WindowsDeployService:
    def __init__(
        self,
        catalog_path: str,
        logger: Callable[[str], None] | None = None,
        stage_logger: Callable[[str], None] | None = None,
    ):
        self.catalog_path = catalog_path
        self.logger = logger or (lambda _msg: None)
        self.stage_logger = stage_logger or (lambda _stage: None)

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
            remote_temp_dir=runtime.remote_temp_dir or "C:\\Windows\\Temp\\tshelper_deploy",
        )
        backend.validate_context(context)
        detection = backend.run_detection(package, context)
        return detection, backend.name

    def install_package(self, package_id: str, force_reinstall: bool, runtime: WindowsDeployRuntime):
        catalog = WindowsSoftwareCatalog.load(self.catalog_path)
        package = catalog.get(package_id)
        backend = self._build_backend(runtime)
        engine = WindowsDeployEngine(backend=backend, logger=self.logger, stage_logger=self.stage_logger)
        options = DeployOptions(
            timeout_sec=max(30, int(runtime.timeout_sec or package.timeout_sec)),
            skip_if_detected=(not force_reinstall) and runtime.skip_if_detected,
            skip_pre_detection=runtime.skip_pre_detection,
            prefer_system_context=runtime.prefer_system_context,
            execution_mode=runtime.execution_mode,
            remote_temp_dir=runtime.remote_temp_dir or "C:\\Windows\\Temp\\tshelper_deploy",
            delivery_folder=runtime.delivery_folder or "C:\\Installers\\TSHelper",
        )
        return engine.deploy(package=package, target_host=runtime.target_host, options=options)
