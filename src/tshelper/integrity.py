"""Проверка файлов установки по проверенному архиву официального релиза."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .paths import DATA_DIR, INSTALL_ROOT
from .updater import (
    MANAGED_DIRECTORIES, MANAGED_FILES, ProgressCallback,
    get_latest_release, get_release_for_version, prepare_update, sha256_file,
)


IGNORED_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache"}
IGNORED_SUFFIXES = {".pyc", ".pyo", ".log"}


class IntegrityCancelled(RuntimeError):
    """Пользователь отменил проверку."""


@dataclass(frozen=True)
class IntegrityIssue:
    path: str
    status: str
    detail: str = ""


@dataclass
class IntegrityReport:
    version: str
    latest_version: str = ""
    latest_error: str = ""
    reference_error: str = ""
    checked: int = 0
    matched: int = 0
    issues: list[IntegrityIssue] = field(default_factory=list)

    def summary(self) -> str:
        if self.reference_error:
            integrity = f"Целостность не проверена: {self.reference_error}"
        elif self.issues:
            integrity = f"Обнаружены расхождения: {len(self.issues)}. Совпало файлов: {self.matched} из {self.checked}."
        else:
            integrity = f"Файлы соответствуют релизу v{self.version}. Проверено: {self.checked}."
        if self.latest_error:
            freshness = f"Актуальность версии не проверена: {self.latest_error}"
        elif self.latest_version:
            installed = tuple(int(part) for part in self.version.split("."))
            latest = tuple(int(part) for part in self.latest_version.split("."))
            length = max(len(installed), len(latest))
            installed += (0,) * (length - len(installed))
            latest += (0,) * (length - len(latest))
            if latest > installed:
                freshness = f"Доступно обновление: v{self.latest_version}. Установлена v{self.version}."
            elif latest == installed:
                freshness = f"Версия актуальна: v{self.version}."
            else:
                freshness = f"Установленная v{self.version} новее опубликованной v{self.latest_version}."
        else:
            freshness = "Актуальность версии не проверена."
        return integrity + "\n" + freshness

    def as_text(self) -> str:
        lines = [self.summary(), "", "Путь\tРезультат\tПодробности"]
        lines.extend(f"{item.path}\t{item.status}\t{item.detail}" for item in self.issues)
        return "\n".join(lines)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()) or (
        os.name == "nt" and path.exists()
        and bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    )


def _inventory(root: Path, progress: ProgressCallback | None = None) -> dict[str, str]:
    """Обойти только поставляемые каталоги, не переходя по ссылкам и junction."""
    result = {}

    def register(path: Path):
        if progress:
            progress("Сканирование состава файлов", 0, 0)
        relative = path.relative_to(root).as_posix()
        if _is_link(path):
            result[relative] = "Ссылка или точка соединения"
        elif path.is_dir():
            with os.scandir(path) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if child.name.lower() in IGNORED_DIRECTORIES or child.suffix.lower() in IGNORED_SUFFIXES:
                        continue
                    register(child)
        else:
            result[relative] = ""

    for name in (*MANAGED_DIRECTORIES, *MANAGED_FILES):
        path = root / name
        if path.exists() or path.is_symlink():
            register(path)
    return result


def compare_installation(
    reference_root: Path, install_root: Path, report: IntegrityReport,
    progress: ProgressCallback | None = None,
) -> IntegrityReport:
    expected = _inventory(reference_root, progress)
    actual = _inventory(install_root, progress)
    if not expected:
        raise ValueError("Эталон не содержит файлов приложения")
    for index, relative in enumerate(sorted(expected), 1):
        if progress:
            progress("Сравнение SHA-256 файлов", index, len(expected))
        report.checked += 1
        try:
            if expected[relative]:
                raise ValueError("Эталон содержит ссылку")
            target = install_root / relative
            # Не читаем файл через ссылку в любом родительском каталоге.
            parents = [target, *list(target.parents)[:len(Path(relative).parts) - 1]]
            if any(_is_link(parent) for parent in parents):
                report.issues.append(IntegrityIssue(relative, "Недопустимая ссылка"))
            elif not target.exists():
                report.issues.append(IntegrityIssue(relative, "Отсутствует"))
            elif not target.is_file():
                report.issues.append(IntegrityIssue(relative, "Вместо файла каталог"))
            elif sha256_file(target) != sha256_file(reference_root / relative):
                report.issues.append(IntegrityIssue(relative, "Изменён", "SHA-256 не совпадает с релизом"))
            else:
                report.matched += 1
        except OSError as exc:
            report.issues.append(IntegrityIssue(relative, "Ошибка чтения", str(exc)))
    expected_names = {name.casefold() if os.name == "nt" else name for name in expected}
    extra_names = (
        name for name in actual
        if (name.casefold() if os.name == "nt" else name) not in expected_names
    )
    for relative in sorted(extra_names):
        report.issues.append(IntegrityIssue(relative, "Нет в эталоне", actual[relative]))
    return report


def check_integrity(
    version: str, *, install_root: Path = INSTALL_ROOT,
    cache_root: Path | None = None, progress: ProgressCallback | None = None,
    http_client=None,
) -> IntegrityReport:
    report = IntegrityReport(version=version.lstrip("vV"))
    latest = None
    if progress:
        progress("Проверка актуальности версии", 0, 0)
    try:
        latest = get_latest_release(http_client=http_client)
        report.latest_version = latest.version
    except Exception as exc:
        report.latest_error = str(exc)
    if progress:
        progress("Получение эталона установленной версии", 0, 0)
    try:
        reference = latest if latest and latest.version == report.version else get_release_for_version(
            report.version, http_client=http_client,
        )
        def reference_progress(stage: str, current: int, total: int):
            if progress:
                stage = {
                    "Загрузка обновления": "Загрузка эталонного архива",
                    "Распаковка обновления": "Подготовка эталона",
                    "Обновление готово к установке": "Эталон готов к сравнению",
                }.get(stage, stage)
                progress(stage, current, total)

        prepared = prepare_update(
            reference, progress=reference_progress, update_root=cache_root or DATA_DIR / "integrity",
            http_client=http_client,
        )
        compare_installation(prepared.package_root, install_root.resolve(), report, progress)
    except IntegrityCancelled:
        raise
    except Exception as exc:
        report.reference_error = str(exc)
    return report
