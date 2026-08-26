"""Безопасная подготовка и запуск самообновления portable-версии TSHelper."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from uuid import uuid4

from .paths import DATA_DIR, INSTALL_ROOT


RELEASE_API_URL = "https://api.github.com/repos/Et0ZheMax/tshelper/releases/latest"
MAX_ARCHIVE_SIZE = 300 * 1024 * 1024
MAX_EXTRACTED_SIZE = 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000

MANAGED_DIRECTORIES = ("src", "apps", "assets", "config", "scripts")
MANAGED_FILES = (
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "requirements.txt",
    "pyproject.toml",
    "run_tshelper.bat",
)
REQUIRED_PACKAGE_PATHS = (
    "src/tshelper/version.py",
    "scripts/apply_update.ps1",
    "requirements.txt",
    "pyproject.toml",
    "run_tshelper.bat",
)

ProgressCallback = Callable[[str, int, int], None]


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    tag: str
    version: str
    html_url: str
    asset_name: str
    asset_url: str
    asset_digest: str
    asset_size: int


@dataclass(frozen=True, slots=True)
class PreparedUpdate:
    release: ReleaseInfo
    archive_path: Path
    package_root: Path
    work_directory: Path


def _release_version(tag: str) -> str:
    match = re.fullmatch(r"[vV]?(\d+(?:\.\d+)*)", str(tag or "").strip())
    if not match:
        raise UpdateError(f"Некорректный тег релиза: {tag!r}")
    return match.group(1)


def select_release_asset(payload: dict[str, Any]) -> ReleaseInfo:
    """Выбирает строго именованный portable ZIP и обязательный SHA-256."""
    tag = str(payload.get("tag_name") or payload.get("name") or "").strip()
    version = _release_version(tag)
    expected_name = f"TSHelper-v{version}-portable.zip"
    assets = payload.get("assets") if isinstance(payload.get("assets"), list) else []
    asset = next(
        (item for item in assets if isinstance(item, dict) and item.get("name") == expected_name),
        None,
    )
    if asset is None:
        raise UpdateError(f"В релизе {tag} отсутствует файл {expected_name}")

    url = str(asset.get("browser_download_url") or "").strip()
    digest = str(asset.get("digest") or "").strip().lower()
    size = int(asset.get("size") or 0)
    if not url.startswith("https://github.com/Et0ZheMax/tshelper/releases/download/"):
        raise UpdateError("GitHub Release вернул неожиданный адрес файла обновления")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise UpdateError("У файла релиза отсутствует проверяемый SHA-256")
    if size <= 0 or size > MAX_ARCHIVE_SIZE:
        raise UpdateError(f"Некорректный размер файла обновления: {size}")

    return ReleaseInfo(
        tag=tag,
        version=version,
        html_url=str(payload.get("html_url") or "https://github.com/Et0ZheMax/tshelper/releases"),
        asset_name=expected_name,
        asset_url=url,
        asset_digest=digest.split(":", 1)[1],
        asset_size=size,
    )


def get_latest_release(timeout: int = 10, http_client=None) -> ReleaseInfo:
    if http_client is None:
        try:
            import requests
        except ImportError as exc:
            raise UpdateError("Для проверки обновлений не установлен requests") from exc
        http_client = requests
    response = http_client.get(
        RELEASE_API_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "TSHelper-Updater"},
        timeout=timeout,
    )
    if int(getattr(response, "status_code", 0)) != 200:
        raise UpdateError(f"GitHub API вернул HTTP {getattr(response, 'status_code', '?')}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise UpdateError("GitHub API вернул некорректное описание релиза")
    return select_release_asset(payload)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_release(
    release: ReleaseInfo,
    work_directory: Path,
    progress: ProgressCallback | None = None,
    http_client=None,
) -> Path:
    work_directory.mkdir(parents=True, exist_ok=True)
    archive = work_directory / release.asset_name
    if archive.is_file() and archive.stat().st_size == release.asset_size:
        if sha256_file(archive) == release.asset_digest:
            if progress:
                progress("Архив уже загружен и проверен", release.asset_size, release.asset_size)
            return archive
        archive.unlink()

    if http_client is None:
        try:
            import requests
        except ImportError as exc:
            raise UpdateError("Для загрузки обновления не установлен requests") from exc
        http_client = requests

    partial = archive.with_suffix(archive.suffix + ".part")
    if partial.exists():
        partial.unlink()
    response = http_client.get(
        release.asset_url,
        headers={"Accept": "application/octet-stream", "User-Agent": "TSHelper-Updater"},
        stream=True,
        timeout=(10, 60),
    )
    if int(getattr(response, "status_code", 0)) != 200:
        raise UpdateError(f"Не удалось скачать обновление: HTTP {getattr(response, 'status_code', '?')}")

    downloaded = 0
    digest = hashlib.sha256()
    try:
        with partial.open("wb") as target:
            for chunk in response.iter_content(chunk_size=256 * 1024):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > MAX_ARCHIVE_SIZE or downloaded > release.asset_size:
                    raise UpdateError("Файл обновления превысил заявленный размер")
                digest.update(chunk)
                target.write(chunk)
                if progress:
                    progress("Загрузка обновления", downloaded, release.asset_size)
        if downloaded != release.asset_size:
            raise UpdateError(
                f"Загружено {downloaded} байт вместо ожидаемых {release.asset_size}"
            )
        if digest.hexdigest() != release.asset_digest:
            raise UpdateError("SHA-256 загруженного обновления не совпадает с GitHub Release")
        os.replace(partial, archive)
        return archive
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _validate_archive_member(member: zipfile.ZipInfo) -> PurePosixPath:
    raw_name = member.filename.replace("\\", "/")
    path = PurePosixPath(raw_name)
    if (
        not raw_name
        or path.is_absolute()
        or ".." in path.parts
        or any(":" in part for part in path.parts)
    ):
        raise UpdateError(f"Небезопасный путь внутри архива: {member.filename}")
    file_type = (member.external_attr >> 16) & 0o170000
    if file_type == 0o120000:
        raise UpdateError(f"Символические ссылки в обновлении запрещены: {member.filename}")
    return path


def validate_package_root(package_root: Path, expected_version: str) -> None:
    missing = [item for item in REQUIRED_PACKAGE_PATHS if not (package_root / item).is_file()]
    missing.extend(item for item in MANAGED_DIRECTORIES if not (package_root / item).is_dir())
    if missing:
        raise UpdateError("В архиве обновления отсутствуют обязательные пути: " + ", ".join(missing))
    version_source = (package_root / "src/tshelper/version.py").read_text(encoding="utf-8-sig")
    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", version_source, flags=re.MULTILINE)
    if not match or match.group(1) != expected_version:
        actual = match.group(1) if match else "не определена"
        raise UpdateError(f"Версия внутри архива {actual} не совпадает с {expected_version}")


def extract_release_archive(
    release: ReleaseInfo,
    archive: Path,
    work_directory: Path,
    progress: ProgressCallback | None = None,
) -> Path:
    destination = work_directory / "extracted"
    extracting = work_directory / f"extracting-{uuid4().hex}"
    if extracting.exists():
        raise UpdateError(f"Временный каталог уже существует: {extracting}")
    extracting.mkdir(parents=True)
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members or len(members) > MAX_ARCHIVE_ENTRIES:
                raise UpdateError("Некорректное количество файлов в архиве обновления")
            paths = [_validate_archive_member(member) for member in members]
            total_size = sum(member.file_size for member in members)
            if total_size <= 0 or total_size > MAX_EXTRACTED_SIZE:
                raise UpdateError("Некорректный распакованный размер обновления")
            roots = {path.parts[0] for path in paths if path.parts}
            if roots != {f"TSHelper-v{release.version}"}:
                raise UpdateError("Архив должен содержать один корневой каталог версии")
            if progress:
                progress("Проверка архива", 1, 1)
            extracted_size = 0
            for member in members:
                bundle.extract(member, extracting)
                extracted_size += member.file_size
                if progress:
                    progress("Распаковка обновления", extracted_size, total_size)

        package_root = extracting / f"TSHelper-v{release.version}"
        validate_package_root(package_root, release.version)
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(extracting, destination)
        return destination / package_root.name
    except Exception:
        shutil.rmtree(extracting, ignore_errors=True)
        raise


def prepare_update(
    release: ReleaseInfo,
    progress: ProgressCallback | None = None,
    update_root: Path | None = None,
    http_client=None,
) -> PreparedUpdate:
    root = (update_root or DATA_DIR / "updates").resolve()
    work_directory = root / f"v{release.version}"
    work_directory.mkdir(parents=True, exist_ok=True)
    archive = download_release(release, work_directory, progress=progress, http_client=http_client)
    package_root = extract_release_archive(release, archive, work_directory, progress=progress)
    if progress:
        progress("Обновление готово к установке", 1, 1)
    return PreparedUpdate(release, archive, package_root, work_directory)


def find_update_launcher(install_root: Path | None = None) -> Path | None:
    root = (install_root or INSTALL_ROOT).resolve()
    for relative_path in ("run_tshelper.bat", "scripts/run_tshelper.bat"):
        candidate = root / relative_path
        if candidate.is_file():
            return candidate
    return None


def can_self_update(install_root: Path | None = None) -> bool:
    root = (install_root or INSTALL_ROOT).resolve()
    return (
        os.name == "nt"
        and (root / "src/tshelper/version.py").is_file()
        and (root / "pyproject.toml").is_file()
        and find_update_launcher(root) is not None
    )


def launch_prepared_update(
    prepared: PreparedUpdate,
    install_root: Path | None = None,
    current_pid: int | None = None,
) -> subprocess.Popen:
    if os.name != "nt":
        raise UpdateError("Автоматическая установка обновлений поддерживается только в Windows")
    target = (install_root or INSTALL_ROOT).resolve()
    if not can_self_update(target):
        raise UpdateError("Не удалось определить каталог и launcher установленного TSHelper")
    launcher = find_update_launcher(target)
    if launcher is None:
        raise UpdateError("Не найден штатный launcher TSHelper")

    source_script = prepared.package_root / "scripts/apply_update.ps1"
    updater_copy = prepared.work_directory / f"apply-update-{prepared.release.version}.ps1"
    shutil.copy2(source_script, updater_copy)
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise UpdateError("Не найден Windows PowerShell для установки обновления")
    log_path = DATA_DIR / "updater.log"
    command = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", str(updater_copy),
        "-SourceDirectory", str(prepared.package_root),
        "-TargetDirectory", str(target),
        "-WaitForPid", str(current_pid or os.getpid()),
        "-ExpectedVersion", prepared.release.version,
        "-LauncherPath", str(launcher),
        "-LogPath", str(log_path),
    ]
    return subprocess.Popen(
        command,
        cwd=str(prepared.work_directory),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
