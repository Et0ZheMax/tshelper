from __future__ import annotations

import time
from typing import Callable

from windows_catalog_models import BackendContext, DeployOptions, DeployResult, DetectionResult, ExecutionResult, WindowsInstallType, WindowsPackage
from windows_execution_backends import BackendError, WindowsExecutionBackend

SUCCESS_CODES = {0}
REBOOT_CODES = {3010, 1641}


class WindowsDeployEngine:
    def __init__(
        self,
        backend: WindowsExecutionBackend,
        logger: Callable[[str], None] | None = None,
        stage_logger: Callable[[str], None] | None = None,
    ):
        self.backend = backend
        self.logger = logger or (lambda _msg: None)
        self.stage_logger = stage_logger or (lambda _stage: None)

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
        except BackendError as exc:
            err = str(exc)
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status=exc.error_kind if exc.error_kind in {"invalid_target", "transport_failed"} else "transport_failed",
                pre=DetectionResult(False, "not_run", error=err, error_kind=exc.error_kind),
                post=DetectionResult(False, "not_run", error=err, error_kind=exc.error_kind),
                exec_result=None,
                installer_error=err,
            )
        except Exception as exc:
            err = str(exc)
            return self._build_result(
                package=package,
                context=context,
                started_at=started_at,
                status="transport_failed",
                pre=DetectionResult(False, "not_run", error=err, error_kind="transport_failed"),
                post=DetectionResult(False, "not_run", error=err, error_kind="transport_failed"),
                exec_result=None,
                installer_error=err,
            )

        if options.skip_pre_detection:
            self.stage_logger("Pre-check")
            pre = DetectionResult(
                detected=False,
                details="skipped_by_operator",
                error_kind="skipped",
                expected_value="pre_detection",
                current_value="skipped",
            )
            self.logger(f"[deploy] pre-detection {package.package_id}: SKIPPED оператором (skip_pre_detection=true)")
        else:
            self.stage_logger("Pre-check")
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
            self.stage_logger("Копирование payload")
            payload_path = self.backend.prepare_payload(package, context)
            self.logger(f"[deploy] resolved payload: {payload_path}")
            self.stage_logger("Запуск установки")
            self.stage_logger("Ожидание завершения установщика")
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
        self.stage_logger("Post-check")
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

        installer_exit_code = exec_result.exit_code
        installer_success = installer_exit_code in SUCCESS_CODES
        installer_reboot = installer_exit_code in REBOOT_CODES

        if post.detected and installer_reboot:
            return "installed_success_reboot_required"
        if post.detected and installer_success:
            return "installed_success"
        if post.detected:
            return "installed_success_with_warnings"

        if installer_reboot:
            return "installed_success_reboot_required"
        if installer_success:
            return "installed_success_with_warnings"

        if exec_result.error_kind == "elevation_required":
            return "elevation_required"
        if exec_result.timed_out:
            return "timeout"
        if exec_result.transport_error:
            return "transport_failed"
        if post.error and post.error_kind not in {"not_found", "compare_failed"}:
            return "detection_failed"
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
        timeout_hint = ""
        if status == "timeout" and package.install_type == WindowsInstallType.EXE:
            timeout_hint = (
                " Установщик EXE не завершился в отведённое время. "
                "Возможная причина: quiet arguments не подошли для данного инсталлятора. "
                "Попробуйте другой silent preset или custom-аргументы."
            )
            self.logger(f"[deploy] hint: {timeout_hint.strip()}")
        installer_error_text = (installer_error or "").strip()
        if timeout_hint:
            installer_error_text = f"{installer_error_text}\n{timeout_hint}".strip()
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
            installer_error=installer_error_text,
            detection_details_before=f"{pre.details}; error={pre.error or '-'}; current={pre.current_value or '-'}",
            detection_details_after=f"{post.details}; error={post.error or '-'}; current={post.current_value or '-'}",
            payload_path_used=exec_result.payload_path_used if exec_result else "",
            executed_command_preview=exec_result.command_preview if exec_result else "",
            pre_detection=pre.to_dict(),
            post_detection=post.to_dict(),
        )
