from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class WindowsInstallType(str, Enum):
    EXE = "exe"
    MSI = "msi"
    MSIX = "msix"
    POWERSHELL = "powershell"
    CMD = "cmd"
    WINGET = "winget"


class SourceKind(str, Enum):
    FILE_PATH = "file_path"
    UNC_PATH = "unc_path"
    URL = "url"
    WINGET_ID = "winget_id"


class RebootBehavior(str, Enum):
    AUTO_DETECT = "auto_detect"
    NEVER = "never"
    ALWAYS = "always"


class Architecture(str, Enum):
    X64 = "x64"
    X86 = "x86"
    ANY = "any"


class DetectionType(str, Enum):
    FILE_EXISTS = "file_exists"
    REGISTRY_EXISTS = "registry_exists"
    REGISTRY_VALUE = "registry_value"
    UNINSTALL_DISPLAY_NAME = "uninstall_display_name"
    PRODUCT_CODE = "product_code"
    COMMAND_SUCCESS = "command_success"
    POWERSHELL_SCRIPT = "powershell_script"


@dataclass(slots=True)
class SourceConfig:
    kind: SourceKind
    value: str
    checksum_sha256: str = ""


@dataclass(slots=True)
class DetectionConfig:
    type: DetectionType
    path: str = ""
    value_name: str = ""
    operator: str = "=="
    value: str = ""
    command: list[str] = field(default_factory=list)
    script: str = ""


@dataclass(slots=True)
class WindowsPackage:
    package_id: str
    title: str
    os_family: str
    install_type: WindowsInstallType
    description: str = ""
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    requires_admin: bool = True
    timeout_sec: int = 1200
    source: SourceConfig = field(default_factory=lambda: SourceConfig(SourceKind.FILE_PATH, ""))
    silent_args: list[str] = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=lambda: DetectionConfig(DetectionType.FILE_EXISTS))
    execution_defaults: dict[str, Any] = field(default_factory=dict)
    package_version: str = ""
    architecture: Architecture = Architecture.ANY
    reboot_behavior: RebootBehavior = RebootBehavior.AUTO_DETECT


@dataclass(slots=True)
class DetectionResult:
    detected: bool
    details: str
    version: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    error_kind: str = ""
    expected_value: str = ""
    current_value: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    transport_error: str = ""
    payload_path_used: str = ""
    command_preview: str = ""
    error_kind: str = ""


@dataclass(slots=True)
class BackendContext:
    target_host: str
    timeout_sec: int
    requires_admin: bool
    prefer_system_context: bool = False
    remote_temp_dir: str = "C:\\Windows\\Temp\\tshelper_deploy"


@dataclass(slots=True)
class DeployOptions:
    timeout_sec: int
    skip_if_detected: bool = True
    prefer_system_context: bool = False


@dataclass(slots=True)
class DeployResult:
    status: str
    start_time: float
    end_time: float
    duration_sec: float
    backend_name: str
    target_host: str
    package_id: str
    pre_detected: bool
    post_detected: bool
    installer_exit_code: int | None
    reboot_required: bool
    stdout: str
    stderr: str
    transport_error: str
    installer_error: str
    detection_details_before: str
    detection_details_after: str
    payload_path_used: str
    executed_command_preview: str
    pre_detection: dict[str, Any] = field(default_factory=dict)
    post_detection: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "backend_name": self.backend_name,
            "target_host": self.target_host,
            "package_id": self.package_id,
            "pre_detected": self.pre_detected,
            "post_detected": self.post_detected,
            "installer_exit_code": self.installer_exit_code,
            "reboot_required": self.reboot_required,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "transport_error": self.transport_error,
            "installer_error": self.installer_error,
            "detection_details_before": self.detection_details_before,
            "detection_details_after": self.detection_details_after,
            "payload_path_used": self.payload_path_used,
            "executed_command_preview": self.executed_command_preview,
            "pre_detection": self.pre_detection,
            "post_detection": self.post_detection,
        }
