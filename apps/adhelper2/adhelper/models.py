from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

Status = Literal["pending", "running", "success", "warning", "failed", "skipped", "simulated"]


@dataclass(slots=True)
class ParsedRequest:
    last_name: str = ""
    first_name: str = ""
    middle_name: str = ""
    has_photo: bool = False
    manager_name: str = ""
    management: str = ""
    department: str = ""
    title: str = ""
    start_date: str = ""
    work_mode: str = ""
    office_room: str = ""
    need_mail: bool = False
    need_internal_phone: bool = False
    mobile_phone: str = ""
    equipment: str = ""
    office_os: str = ""
    need_servers_access: bool = False
    need_folders_access: bool = False
    notes: str = ""

    @property
    def display_name(self) -> str:
        return " ".join(x for x in (self.last_name, self.first_name, self.middle_name) if x).strip()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DomainConfig:
    name: str
    label: str
    netbios: str
    server: str
    search_base: str
    ou_dn: str
    upn_suffix: str
    email_suffix: str
    fired_ou_dn: str
    group_search_base: str = ""
    profile: str = "standard"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DomainConfig":
        name = str(value.get("name") or "").strip()
        profile = str(value.get("profile") or ("omg" if name == "omg-cspfmba" else "standard")).strip().lower()
        if profile not in {"standard", "omg"}:
            profile = "standard"
        return cls(
            name=name,
            label=str(value.get("label") or name).strip(),
            netbios=str(value.get("netbios") or "").strip(),
            server=str(value.get("server") or "").strip(),
            search_base=str(value.get("search_base") or "").strip(),
            ou_dn=str(value.get("ou_dn") or "").strip(),
            upn_suffix=str(value.get("upn_suffix") or "").strip(),
            email_suffix=str(value.get("email_suffix") or "").strip(),
            fired_ou_dn=str(value.get("fired_ou_dn") or "").strip(),
            group_search_base=str(value.get("group_search_base") or "").strip(),
            profile=profile,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class UserRecord:
    domain: str
    display_name: str = ""
    sam: str = ""
    upn: str = ""
    dn: str = ""
    enabled: bool = True
    mail: str = ""
    title: str = ""
    department: str = ""
    division: str = ""
    section: str = ""
    office: str = ""
    telephone: str = ""
    mobile: str = ""
    otp_mobile: str = ""
    manager_name: str = ""
    manager_dn: str = ""
    street_address: str = ""
    description: str = ""
    guid: str = ""
    is_fired: bool = False
    member_of: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, item: dict[str, Any]) -> "UserRecord":
        return cls(
            domain=str(item.get("domain") or ""),
            display_name=str(item.get("displayName") or item.get("display_name") or ""),
            sam=str(item.get("sam") or item.get("samAccountName") or ""),
            upn=str(item.get("upn") or item.get("userPrincipalName") or ""),
            dn=str(item.get("dn") or item.get("distinguishedName") or ""),
            enabled=bool(item.get("enabled", True)),
            mail=str(item.get("mail") or ""),
            title=str(item.get("title") or ""),
            department=str(item.get("department") or ""),
            division=str(item.get("division") or ""),
            section=str(item.get("section") or ""),
            office=str(item.get("office") or item.get("physicalDeliveryOfficeName") or ""),
            telephone=str(item.get("telephoneNumber") or item.get("telephone") or ""),
            mobile=str(item.get("mobile") or ""),
            otp_mobile=str(item.get("otpMobile") or item.get("otp_mobile") or ""),
            manager_name=str(item.get("managerName") or item.get("manager_name") or ""),
            manager_dn=str(item.get("managerDn") or item.get("manager_dn") or ""),
            street_address=str(item.get("streetAddress") or item.get("street_address") or ""),
            description=str(item.get("description") or ""),
            guid=str(item.get("guid") or ""),
            is_fired=bool(item.get("isFired") or item.get("is_fired")),
            member_of=list(item.get("memberOf") or item.get("member_of") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StepResult:
    key: str
    title: str
    status: Status = "pending"
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    def start(self) -> None:
        self.status = "running"
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")

    def finish(self, status: Status, message: str = "", data: dict[str, Any] | None = None) -> None:
        self.status = status
        self.message = message
        if data is not None:
            self.data = data
        self.finished_at = datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass(slots=True)
class OperationResult:
    operation_type: str
    subject: str
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: Status = "pending"
    started_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))
    finished_at: str = ""
    operator: str = ""
    steps: list[StepResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def close(self, status: Status) -> None:
        self.status = status
        self.finished_at = datetime.now().astimezone().isoformat(timespec="seconds")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
