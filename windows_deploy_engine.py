from __future__ import annotations

import time
from typing import Callable

from windows_catalog_models import BackendContext, DeployOptions, DeployResult, DetectionResult, ExecutionResult, WindowsPackage
from windows_execution_backends import WindowsExecutionBackend

SUCCESS_CODES = {0}
REBOOT_CODES = {3010, 1641}


class WindowsDeployEngine:
    def __init__(self, backend: WindowsExecutionBackend, logger: Callable[[str], None] | None = None):
        self.backend = backend
        self.logger = logger or (lambda _msg: None)

    def deploy(
        self,
        package: WindowsPackage,
        target_host: str,
        options: DeployOptions,
    ) -> DeployResult:
        started_at = time.time()
        context = BackendContext(
            target_host=target_host,
            timeout_sec=max(30, int(options.timeout_sec or package.timeout_sec)),
            requires_admin=package.requires_admin,
            prefer_system_context=options.prefer_system_context,
        )
        try:
            self.backend.validate_context(context)
        except Exception as exc:
            err = str(exc)
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="invalid_target" if "invalid_target" in err else "transport_failed",
                pre=DetectionResult(False, "not_run", error=err, error_kind="invalid_target"),
                post=DetectionResult(False, "not_run", error=err, error_kind="invalid_target"),
                exec_result=None,
                installer_error=err,
            )

        pre = self.backend.run_detection(package, context)
        self.logger(f"[deploy] pre-detection {package.package_id}: detected={pre.detected}, details={pre.details}, error={pre.error or '-'}")
        if pre.error and pre.error_kind not in {"not_found", "compare_failed"}:
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="detection_failed",
                pre=pre,
                post=pre,
                exec_result=None,
                installer_error=pre.error,
            )
        if pre.detected and options.skip_if_detected:
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="already_installed",
                pre=pre,
                post=pre,
                exec_result=None,
            )

        payload_path = ""
        exec_result: ExecutionResult | None = None
        installer_error = ""
        try:
            payload_path = self.backend.prepare_payload(package, context)
            self.logger(f"[deploy] resolved payload: {payload_path}")
            exec_result = self.backend.run_install(package, context, payload_path)
            self.logger(f"[deploy] installer exit={exec_result.exit_code} timeout={exec_result.timed_out}")
        except FileNotFoundError as exc:
            installer_error = str(exc)
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="source_unavailable",
                pre=pre,
                post=pre,
                exec_result=None,
                installer_error=installer_error,
            )
        except Exception as exc:
            installer_error = str(exc)
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="transport_failed",
                pre=pre,
                post=pre,
                exec_result=exec_result,
                installer_error=installer_error,
            )
        finally:
            if payload_path:
                self.backend.cleanup(payload_path, context)

        post = self.backend.run_detection(package, context)
        self.logger(f"[deploy] post-detection {package.package_id}: detected={post.detected}, details={post.details}, error={post.error or '-'}")
        status = self._resolve_status(exec_result, post)

        return self._build_result(
            package=package,
            context=context,
            started_at=started_at,
            status=status,
            pre=pre,
            post=post,
            exec_result=exec_result,
            installer_error=installer_error,
        )

    def _resolve_status(self, exec_result: ExecutionResult | None, post: DetectionResult) -> str:
        if exec_result is None:
            return "install_failed"
        if exec_result.error_kind == "elevation_required":
            return "elevation_required"
        if exec_result.timed_out:
            return "timeout"
        if exec_result.transport_error:
            return "transport_failed"
        if post.error and post.error_kind not in {"not_found", "compare_failed"}:
            return "detection_failed"
        if post.detected and exec_result.exit_code in REBOOT_CODES:
            return "installed_success_reboot_required"
        if post.detected and exec_result.exit_code in SUCCESS_CODES:
            return "installed_success"
        if post.detected and exec_result.exit_code not in SUCCESS_CODES | REBOOT_CODES:
            return "installed_success_with_warnings"
        if exec_result.exit_code in REBOOT_CODES:
            return "installed_success_reboot_required" if post.detected else "install_failed"
        return "install_failed"

    def _build_result(
        self,
        package: WindowsPackage,
        context: BackendContext,
        started_at: float,
        status: str,
        pre: DetectionResult,
        post: DetectionResult,
        exec_result: ExecutionResult | None,
        installer_error: str = "",
    ) -> DeployResult:
        ended = time.time()
        exit_code = exec_result.exit_code if exec_result else None
        reboot_required = exit_code in REBOOT_CODES if exit_code is not None else False
        return DeployResult(
            status=status,
            start_time=started_at,
            end_time=ended,
            duration_sec=round(ended - started_at, 3),
            backend_name=self.backend.name,
            target_host=context.target_host,
            package_id=package.package_id,
            pre_detected=bool(pre.detected),
            post_detected=bool(post.detected),
            installer_exit_code=exit_code,
            reboot_required=reboot_required,
            stdout=exec_result.stdout if exec_result else "",
            stderr=exec_result.stderr if exec_result else "",
            transport_error=exec_result.transport_error if exec_result else "",
            installer_error=installer_error,
            detection_details_before=f"{pre.details}; error={pre.error or '-'}; current={pre.current_value or '-'}",
            detection_details_after=f"{post.details}; error={post.error or '-'}; current={post.current_value or '-'}",
            payload_path_used=exec_result.payload_path_used if exec_result else "",
            executed_command_preview=exec_result.command_preview if exec_result else "",
            pre_detection=pre.to_dict(),
            post_detection=post.to_dict(),
        )
