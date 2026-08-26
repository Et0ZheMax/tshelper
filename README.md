# TSHelper v5.13.2

TSHelper — Windows desktop-рабочее место инженера техподдержки: поиск сотрудников и компьютеров, Active Directory, GLPI, CallWatcher, SSH/PowerShell Remote, удалённая установка ПО и мониторинг принтеров в одном интерфейсе.

## Что под капотом

- **Движок:** Python 3.11+ и Tkinter/ttk; сетевые и длительные операции вынесены из UI-потока.
- **Windows и AD:** LDAP (`ldap3`), PowerShell/RSAT, WinRM/PsExec, DPAPI и Windows Credential Manager.
- **Linux automation:** SSH/Paramiko, управляемый sudoers-профиль и JSON-каталог пакетов.
- **Интеграции:** GLPI API, локальный browser bridge и парсинг FreePBX для CallWatcher.
- **Встроенные приложения:** ADHelper 2.1.0 на PySide6 и Print Monitor на SNMP/HTTP.
- **Хранение:** локальные JSON-файлы в `%APPDATA%\TSHelper`; секреты — в Keyring/DPAPI.

## Возможности

- карточки пользователей, быстрый поиск, импорт/экспорт и проверка доступности хостов;
- раздельное контекстное меню для Windows и Linux с опциональным объединением действий;
- несколько Windows/Linux-компьютеров в одной карточке, отдельные OS-бейджи и точный выбор целевого хоста;
- внутренний номер и местоположение пользователя в одной строке карточки;
- отзывчивый интерфейс: фоновые AD/GLPI Sync, ограниченная ping-очередь и инкрементальная отрисовка карточек;
- синхронизация с Active Directory и GLPI;
- открытие пользователя во встроенном ADHelper 2;
- управление группами доступа и контроль соответствия OU организационным атрибутам через ADHelper 2.1.0;
- связанные списки `department` и `section` в карточке AD: управление фильтрует отделы, а отдел подставляет своё управление;
- входящие звонки FreePBX с поднятием карточки звонящего;
- SSH, Termius, PowerShell Remote и копирование рабочих каталогов на удалённый ПК;
- установка ПО на Ubuntu и Windows из редактируемых каталогов;
- отдельный Print Monitor без блокировки главного окна;
- системный трей, журнал действий и защищённое хранение учётных данных.
- безопасное самообновление из GitHub Releases для portable-сборки и штатного запуска из репозитория: периодическая проверка, наглядный прогресс, SHA-256, резервная копия, замена файлов и автоматический перезапуск.

## Структура репозитория

```text
tshelper/
├── src/tshelper/       # основной Python-пакет и UI
├── apps/adhelper2/     # встроенный ADHelper 2
├── assets/             # иконки и изображения
├── config/             # поставляемые каталоги ПО и пример
├── docs/               # архитектурная документация
├── tests/              # быстрые регрессионные проверки
└── scripts/            # запуск и воспроизводимая релизная сборка
```

Старая отдельная версия `TS HELP AD v3.8.py` удалена. Классический ADHelper сохранён в `apps/adhelper_classic.py` для совместимости, основной TSHelper использует `apps/adhelper2`.

## Установка и запуск

Требуются Windows 10/11 и Python 3.11 или новее. Для AD-операций нужны PowerShell и модуль Active Directory из RSAT.

```powershell
git clone https://github.com/Et0ZheMax/tshelper.git
cd tshelper
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e . --no-deps
.venv\Scripts\python -m tshelper
```

Можно запустить `scripts\run_tshelper.bat`: он создаст окружение и установит зависимости при первом старте.

## Данные и конфигурация

Рабочие файлы не создаются в репозитории. Они находятся в `%APPDATA%\TSHelper`:

- `config.json` — настройки приложения;
- `users.json` — база карточек;
- `dock_items.json` — кнопки док-панели;
- `software_catalog*.json` — редактируемые копии каталогов ПО;
- `app.log` и `_pbx_debug` — журнал и диагностические дампы.

При первом запуске TSHelper копирует найденные файлы старой раскладки из корня установки. Альтернативный каталог можно задать переменной `TSHELPER_DATA_DIR`.

По умолчанию контекстное меню фильтруется по ОС конкретного ПК. Чтобы вернуть полный набор команд для всех карточек, включите **Настройки → Общее → Объединить функционал контекстного меню для Windows и Linux**. Местоположение берётся из AD-атрибута `physicalDeliveryOfficeName` (с fallback на `l`) и также доступно при ручном редактировании карточки.

Пароли AD, SSH, GLPI и FreePBX сохраняются в Windows Credential Manager через `keyring`; при необходимости используется DPAPI-файл. Секреты не должны добавляться в Git.

## Разработка

```powershell
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
python -m compileall -q src tests
python tests/selftest.py
```

Подробности устройства проекта: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Правила изменений: [CONTRIBUTING.md](CONTRIBUTING.md).

## Релизы и версии

Единственный источник версии — `src/tshelper/version.py`. Теги публикуются в формате `vX.Y.Z`; релизный workflow проверяет совпадение тега с кодом и прикладывает portable ZIP.

Проверка обновлений сравнивает версии численно: старый GitHub Release никогда не объявляется новым только из-за отличия строки тега.

Локальная сборка:

```powershell
.\scripts\build_release.ps1
```

История изменений: [CHANGELOG.md](CHANGELOG.md). Готовые версии: [GitHub Releases](https://github.com/Et0ZheMax/tshelper/releases).
