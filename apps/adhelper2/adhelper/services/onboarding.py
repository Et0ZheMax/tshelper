from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..constants import COMPANY_NAME, OMG_DIVISION_VALUE
from ..models import DomainConfig, OperationResult, ParsedRequest, StepResult
from ..organization import get_omg_department_section, get_pak_department
from ..utils import normalize_phone, operator_info
from .ad_service import ADService
from .audit import AuditRepository
from .ou_resolver import OUResolver
from .welcome import WelcomeDocumentService, select_welcome_domain


@dataclass(slots=True)
class DomainPlan:
    domain: DomainConfig
    target_ou: str
    department: str
    section: str = ""
    division: str = ""
    manager_dn: str = ""
    manager_name: str = ""
    warnings: list[str] = field(default_factory=list)
    manager_candidates: list[dict[str, str]] = field(default_factory=list)
    ou_candidates: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class OnboardingPlan:
    request: ParsedRequest
    sam: str
    address: str
    address_meta: dict[str, str]
    password: str
    domains: list[DomainPlan]
    duplicate_users: list[dict[str, Any]] = field(default_factory=list)
    create_welcome: bool = True
    print_welcome: bool = False


class OnboardingService:
    def __init__(
        self,
        ad: ADService,
        ou_resolver: OUResolver,
        audit: AuditRepository,
        welcome: WelcomeDocumentService,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.ad = ad
        self.ou_resolver = ou_resolver
        self.audit = audit
        self.welcome = welcome
        self.logger = logger or (lambda _message: None)

    def build_plan(
        self,
        request: ParsedRequest,
        selected_domains: list[str],
        address: str,
        password: str,
        address_meta: dict[str, str] | None = None,
        explicit_ous: dict[str, str] | None = None,
        progress: Callable[[str, str], None] | None = None,
    ) -> OnboardingPlan:
        if not request.first_name or not request.last_name:
            raise ValueError("Для создания обязательны имя и фамилия")
        if not password:
            raise ValueError("Пароль по умолчанию не задан")
        address = str(address or "").strip()
        if not address:
            raise ValueError("Адрес офиса не указан")
        progress = progress or (lambda _key, _message: None)

        progress("duplicates", "Проверяем совпадения ФИО в выбранных доменах…")
        possible_duplicates = self.ad.search_users(request.display_name, selected_domains, include_fired=True)
        duplicate_users = [user.to_dict() for user in possible_duplicates if user.display_name.strip().casefold() == request.display_name.strip().casefold()]

        progress("login", "Подбираем свободный логин во всех настроенных доменах…")
        sam = self.ad.generate_sam(request.first_name, request.last_name)
        plans: list[DomainPlan] = []
        explicit_ous = explicit_ous or {}
        for domain_name in selected_domains:
            domain = self.ad.domain_by_name[domain_name]
            progress(
                domain.name,
                f"{domain.label}: определяем атрибуты, руководителя и целевой OU…",
            )
            warnings: list[str] = []
            ou_candidates: list[dict[str, Any]] = []
            if domain.profile == "omg":
                department, section = get_omg_department_section(request)
                target_ou = explicit_ous.get(domain.name, "")
                if not target_ou:
                    resolution = self.ou_resolver.resolve(domain, request.department or department, domain.ou_dn)
                    ou_candidates = list(resolution.candidates or [])
                    target_ou = resolution.selected_dn or domain.ou_dn
                    if not resolution.selected_dn:
                        warnings.append("OU не определён однозначно — выбран базовый OU; можно выбрать кандидата вручную")
                division = OMG_DIVISION_VALUE
            else:
                department = get_pak_department(request)
                section = ""
                division = ""
                target_ou = explicit_ous.get(domain.name) or domain.ou_dn
            manager_dn = ""
            manager_name = request.manager_name
            manager_candidates: list[dict[str, str]] = []
            if manager_name:
                managers = self.ad.find_managers(manager_name, domain.name)
                manager_candidates = [
                    {"display_name": manager.display_name, "sam": manager.sam, "dn": manager.dn, "department": manager.department}
                    for manager in managers
                ]
                if len(managers) == 1:
                    manager_dn = managers[0].dn
                    manager_name = managers[0].display_name
                elif not managers:
                    warnings.append("Руководитель не найден; Manager не будет установлен")
                else:
                    warnings.append("Найдено несколько руководителей; выберите правильного в плане")
            plans.append(DomainPlan(
                domain=domain,
                target_ou=target_ou,
                department=department,
                section=section,
                division=division,
                manager_dn=manager_dn,
                manager_name=manager_name,
                warnings=warnings,
                manager_candidates=manager_candidates,
                ou_candidates=ou_candidates,
            ))
        progress("complete", "План AD сформирован. Открываем проверку перед выполнением…")
        return OnboardingPlan(
            request=request,
            sam=sam,
            address=address,
            address_meta=dict(address_meta or {}),
            password=password,
            domains=plans,
            duplicate_users=duplicate_users,
        )

    def execute(self, plan: OnboardingPlan, dry_run: bool = False, progress: Callable[[str, str], None] | None = None) -> OperationResult:
        progress = progress or (lambda _key, _message: None)
        operation = OperationResult("onboarding", plan.request.display_name, operator=operator_info()["username"])
        operation.data["sam"] = plan.sam
        operation.data["domains"] = [item.domain.name for item in plan.domains]
        successful: list[dict[str, Any]] = []
        try:
            for item in plan.domains:
                step = StepResult(item.domain.name, f"Создание в {item.domain.label}")
                operation.steps.append(step)
                step.start()
                progress(item.domain.name, f"Создание пользователя в {item.domain.label}")
                try:
                    payload = self._build_payload(plan, item)
                    result = self.ad.create_user(item.domain, payload, dry_run=dry_run)
                    successful.append({"domain": item.domain.name, "result": result, "payload": payload})
                    status = "simulated" if dry_run else "success"
                    step.finish(status, "Пользователь создан" if not dry_run else "Проверка выполнена", result)
                    operation.warnings.extend(item.warnings)
                except Exception as exc:
                    step.finish("failed", str(exc))
                    operation.errors.append(f"[{item.domain.name}] {exc}")
            if successful and not dry_run and plan.create_welcome:
                step = StepResult("welcome", "Приветственный документ")
                operation.steps.append(step)
                step.start()
                progress("welcome", "Создание приветственного документа")
                try:
                    print_domain = select_welcome_domain(item.domain for item in plan.domains)
                    email = plan.sam + print_domain.email_suffix if plan.request.need_mail else ""
                    path = self.welcome.generate(
                        login=plan.sam,
                        domain_login=f"{print_domain.netbios}\\{plan.sam}",
                        email=email,
                        password=plan.password,
                    )
                    if plan.print_welcome:
                        self.welcome.print_document(path)
                    operation.data["welcome_path"] = str(path)
                    step.finish("success", "Документ создан", {"path": str(path), "printed": plan.print_welcome})
                except Exception as exc:
                    operation.warnings.append(f"Приветственный документ: {exc}")
                    step.finish("warning", str(exc))
            if operation.errors and successful:
                operation.close("warning")
            elif operation.errors:
                operation.close("failed")
            else:
                operation.close("simulated" if dry_run else "success")
            return operation
        finally:
            if not operation.finished_at:
                operation.close("failed")
            self.audit.save(operation)

    @staticmethod
    def _build_payload(plan: OnboardingPlan, domain_plan: DomainPlan) -> dict[str, Any]:
        request = plan.request
        address_meta = dict(plan.address_meta)
        mobile = normalize_phone(request.mobile_phone)
        is_omg = domain_plan.domain.profile == "omg"
        return {
            "sam": plan.sam,
            "upn": plan.sam + domain_plan.domain.upn_suffix,
            "display_name": request.display_name,
            "first_name": request.first_name,
            "last_name": request.last_name,
            "middle_name": request.middle_name,
            "password": plan.password,
            "title": request.title.strip().lower(),
            "department": domain_plan.department,
            "division": domain_plan.division,
            "section": domain_plan.section,
            "company": COMPANY_NAME,
            "office": request.office_room,
            "street_address": plan.address,
            "address_meta": address_meta,
            "description": request.title.strip().lower(),
            "mail": plan.sam + domain_plan.domain.email_suffix if request.need_mail else "",
            "mobile": "" if is_omg else mobile,
            "otp_mobile": mobile if is_omg else "",
            "manager_dn": domain_plan.manager_dn,
            "target_ou": domain_plan.target_ou,
            "change_password_at_logon": True,
        }
