from __future__ import annotations

import re
import subprocess
from decimal import Decimal, InvalidOperation
from typing import Callable, Sequence

from windows_catalog_models import DetectionConfig, DetectionResult, DetectionType

CommandExecutor = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]
_SUPPORTED_OPERATORS = {"==", "!=", ">", "<", ">=", "<="}


def run_subprocess_command(command: Sequence[str], timeout_sec: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def run_detection(config: DetectionConfig, timeout_sec: int = 30) -> DetectionResult:
    return run_detection_with_executor(config=config, executor=run_subprocess_command, timeout_sec=timeout_sec)


def run_detection_with_executor(config: DetectionConfig, executor: CommandExecutor, timeout_sec: int = 30) -> DetectionResult:
    try:
        if config.type == DetectionType.FILE_EXISTS:
            cp = executor(["cmd.exe", "/c", "if", "exist", config.path, "(exit", "0)", "else", "(exit", "1)"], timeout_sec)
            return DetectionResult(
                detected=cp.returncode == 0,
                details=f"file_exists: {config.path}",
                raw_output=(cp.stdout or "") + (cp.stderr or ""),
                error=None if cp.returncode == 0 else "Файл не найден",
                error_kind="not_found" if cp.returncode != 0 else "",
            )

        if config.type == DetectionType.REGISTRY_EXISTS:
            cp = executor(["reg", "query", config.path], timeout_sec)
            return DetectionResult(
                detected=cp.returncode == 0,
                details=f"registry_exists: {config.path}",
                raw_output=(cp.stdout or "") + (cp.stderr or ""),
                error=None if cp.returncode == 0 else "Ключ не найден",
                error_kind="not_found" if cp.returncode != 0 else "",
            )

        if config.type == DetectionType.REGISTRY_VALUE:
            return _detect_registry_value(config=config, executor=executor, timeout_sec=timeout_sec)

        if config.type == DetectionType.UNINSTALL_DISPLAY_NAME:
            cp = executor([
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* ,"
                    "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                    "| Select-Object -ExpandProperty DisplayName"
                ),
            ], timeout_sec)
            text = (cp.stdout or "") + (cp.stderr or "")
            detected = cp.returncode == 0 and config.value.lower() in text.lower()
            return DetectionResult(
                detected=detected,
                details="uninstall_display_name",
                raw_output=text,
                error=None if cp.returncode == 0 else f"Код выхода {cp.returncode}",
                error_kind="execution_failed" if cp.returncode != 0 else ("not_found" if not detected else ""),
                expected_value=config.value,
            )

        if config.type == DetectionType.PRODUCT_CODE:
            cp = executor([
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-ChildItem HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall,"
                    "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall "
                    "| Select-Object -ExpandProperty PSChildName"
                ),
            ], timeout_sec)
            text = (cp.stdout or "") + (cp.stderr or "")
            detected = cp.returncode == 0 and config.value.lower() in text.lower()
            return DetectionResult(
                detected=detected,
                details="product_code",
                raw_output=text,
                error=None if cp.returncode == 0 else f"Код выхода {cp.returncode}",
                error_kind="execution_failed" if cp.returncode != 0 else ("not_found" if not detected else ""),
                expected_value=config.value,
            )

        if config.type == DetectionType.COMMAND_SUCCESS:
            cp = executor(config.command, timeout_sec)
            return DetectionResult(
                detected=cp.returncode == 0,
                details="command_success",
                raw_output=(cp.stdout or "") + (cp.stderr or ""),
                error=None if cp.returncode == 0 else f"Код выхода {cp.returncode}",
                error_kind="execution_failed" if cp.returncode != 0 else "",
            )

        if config.type == DetectionType.POWERSHELL_SCRIPT:
            cp = executor(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", config.script], timeout_sec)
            text = ((cp.stdout or "") + (cp.stderr or "")).strip()
            text_lower = text.lower()
            detected = cp.returncode == 0 and text_lower not in {"false", "0", ""}
            return DetectionResult(
                detected=detected,
                details="powershell_script",
                raw_output=text,
                error=None if cp.returncode == 0 else f"Код {cp.returncode}",
                error_kind="execution_failed" if cp.returncode != 0 else ("not_found" if not detected else ""),
            )

        return DetectionResult(False, "unsupported_detection", error=f"Неподдерживаемый detection: {config.type}", error_kind="unsupported")
    except subprocess.TimeoutExpired:
        return DetectionResult(False, "timeout", error=f"Timeout при detection: {config.type.value}", error_kind="timeout")
    except Exception as exc:
        return DetectionResult(False, "error", error=str(exc), error_kind="execution_failed")


def _detect_registry_value(config: DetectionConfig, executor: CommandExecutor, timeout_sec: int) -> DetectionResult:
    cp = executor(["reg", "query", config.path, "/v", config.value_name], timeout_sec)
    raw = (cp.stdout or "") + (cp.stderr or "")
    if cp.returncode != 0:
        return DetectionResult(False, f"registry_value: {config.path}", raw_output=raw, error="Значение не найдено", error_kind="not_found")

    parsed_value = _extract_reg_value(raw, config.value_name)
    if parsed_value is None:
        return DetectionResult(
            False,
            f"registry_value: {config.path}/{config.value_name}",
            raw_output=raw,
            error="Не удалось распарсить значение из reg query",
            error_kind="parse_failed",
        )

    operator = (config.operator or "==").strip()
    if operator not in _SUPPORTED_OPERATORS:
        return DetectionResult(
            False,
            f"registry_value: {config.path}/{config.value_name}",
            raw_output=raw,
            error=f"Оператор не поддерживается: {operator}",
            error_kind="invalid_operator",
            current_value=parsed_value,
            expected_value=config.value,
        )

    compare_ok, compare_error = _compare_values(parsed_value, config.value, operator)
    return DetectionResult(
        detected=compare_ok,
        details=f"registry_value: {config.path}/{config.value_name}; current={parsed_value}; expected {operator} {config.value}",
        raw_output=raw,
        error=compare_error,
        error_kind="" if compare_ok else ("compare_failed" if not compare_error else "execution_failed"),
        current_value=parsed_value,
        expected_value=config.value,
    )


def _extract_reg_value(raw_output: str, value_name: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(value_name)}\s+REG_\w+\s+(.*)$", re.IGNORECASE)
    for line in raw_output.splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    return None


def _compare_values(current_value: str, expected_value: str, operator: str) -> tuple[bool, str | None]:
    left = current_value.strip()
    right = expected_value.strip()

    decimal_compare = _try_decimal_compare(left, right)
    if decimal_compare is not None:
        return _evaluate_relation(decimal_compare, operator), None

    version_compare = _try_version_compare(left, right)
    if version_compare is not None:
        return _evaluate_relation(version_compare, operator), None

    lexical_compare = (left > right) - (left < right)
    return _evaluate_relation(lexical_compare, operator), None


def _evaluate_relation(compare_result: int, operator: str) -> bool:
    return {
        "==": compare_result == 0,
        "!=": compare_result != 0,
        ">": compare_result > 0,
        "<": compare_result < 0,
        ">=": compare_result >= 0,
        "<=": compare_result <= 0,
    }[operator]


def _try_decimal_compare(left: str, right: str) -> int | None:
    try:
        lv = Decimal(left)
        rv = Decimal(right)
    except (InvalidOperation, ValueError):
        return None
    return (lv > rv) - (lv < rv)


def _try_version_compare(left: str, right: str) -> int | None:
    if not (_looks_like_version(left) and _looks_like_version(right)):
        return None
    lparts = [int(part) for part in left.split(".")]
    rparts = [int(part) for part in right.split(".")]
    length = max(len(lparts), len(rparts))
    lparts += [0] * (length - len(lparts))
    rparts += [0] * (length - len(rparts))
    return (lparts > rparts) - (lparts < rparts)


def _looks_like_version(value: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+)+", value.strip()))
