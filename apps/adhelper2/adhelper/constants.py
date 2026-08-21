from __future__ import annotations

from pathlib import Path

APP_NAME = "ADHelper"
APP_VERSION = "2.0.15"
COMPANY_NAME = "ФГБУ «ЦСП» ФМБА России"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = PACKAGE_ROOT / "scripts"
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
WELCOME_TEMPLATE_PATH = TEMPLATES_DIR / "New User.odt"

DOMAIN_CONFIGS = [
    {
        "name": "pak-cspmz",
        "label": "pak-cspmz",
        "netbios": "PAK-CSPMZ",
        "server": "dc03.pak-cspmz.ru",
        "search_base": "DC=pak-cspmz,DC=ru",
        "ou_dn": "OU=omg,OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru",
        "upn_suffix": "@pak-cspmz.ru",
        "email_suffix": "@cspfmba.ru",
        "fired_ou_dn": "OU=Уволенные,OU=Users,OU=csp,DC=pak-cspmz,DC=ru",
        "group_search_base": "OU=Group,OU=csp,DC=pak-cspmz,DC=ru",
        "profile": "standard",
    },
    {
        "name": "omg-cspfmba",
        "label": "omg.cspfmba",
        "netbios": "OMG",
        "server": "DC24.omg.cspfmba.ru",
        "search_base": "DC=omg,DC=cspfmba,DC=ru",
        "ou_dn": "OU=Institute of Synthetic Biology and Genetic Engineering,DC=omg,DC=cspfmba,DC=ru",
        "upn_suffix": "@omg.cspfmba.ru",
        "email_suffix": "@cspfmba.ru",
        "fired_ou_dn": "OU=Уволенные,OU=Users,OU=csp,DC=omg,DC=cspfmba,DC=ru",
        "group_search_base": "",
        "profile": "omg",
    },
]

DOMAIN_BY_NAME = {item["name"]: item for item in DOMAIN_CONFIGS}

OFFICE_ADDRESSES = [
    {
        "address": "ул. Щукинская, дом 5, стр.5",
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "123182",
        "country": "RU",
    },
    {
        "address": "ул. Погодинская, д. 10, стр.2",
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
    {
        "address": "ул. Погодинская, д. 10, стр.1",
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
]

# Совместимые представления для старых импортов и миграции конфигурации.
ADDRESS_CHOICES = [item["address"] for item in OFFICE_ADDRESSES]
ADDRESS_DETAILS = {
    item["address"]: {key: value for key, value in item.items() if key != "address"}
    for item in OFFICE_ADDRESSES
}

OMG_OU_TREE = {
    "outsource": [],
    "отдел научно-технического и методического обеспечения": [],
    "отдел редакционно-издательской деятельности": [],
    "управление организации и проведения исследований": [
        "лаборатория эпигенетических методов исследований",
        "отдел анализа и прогнозирования медико-биологических рисков здоровью",
        "отдел медицинской геномики",
        "отдел организации проведения клинических исследований",
    ],
    "управление цифровых систем и биоинформатики": [
        "отдел архивирования и хранения цифровой информации",
        "отдел информационно-ресурсного обеспечения",
        "отдел системной биологии и биоинформатики",
    ],
    "управление экспериментальной биотехнологии и генной инженерии": [
        "виварий",
        "лаборатория биобанкирования и мультиомиксных методов исследований",
        "лаборатория генной инженерии",
        "лаборатория гистологических исследований",
        "лаборатория иммунологии и клеточной биологии",
        "лаборатория метагеномных исследований",
        "лаборатория микробиологии и паразитологии",
        "лаборатория наноматериалов",
        "лаборатория опасных и социально значимых инфекций",
        "лаборатория разработки биотехнологических процессов",
        "лаборатория синтеза олигонуклеотидов и малых молекул",
        "лаборатория экспериментальных и аналитических исследований",
        "отдел ресурсного сопровождения лабораторий",
        "отдел эксплуатации и обслуживания научного оборудования",
    ],
}

OMG_DIVISION_VALUE = "институт синтетической биологии и генной инженерии"

CLEAR_ATTRIBUTES_COMMON = [
    "title", "department", "company", "physicalDeliveryOfficeName",
    "telephoneNumber", "mobile", "mail", "streetAddress", "l", "st",
    "postalCode", "postOfficeBox", "co", "manager", "description", "info",
]

CLEAR_ATTRIBUTES_OMG = CLEAR_ATTRIBUTES_COMMON + [
    "facsimileTelephoneNumber", "homePhone", "ipPhone", "pager", "wWWHomePage",
    "otherTelephone", "otherMobile", "otherHomePhone", "otherPager",
    *[f"extensionAttribute{i}" for i in range(1, 16)],
    "division", "section", "otpMobile",
]
