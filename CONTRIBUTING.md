# Участие в разработке

1. Создайте ветку от актуальной `main`.
2. Установите зависимости: `python -m pip install -r requirements-dev.txt` и `python -m pip install -e . --no-deps`.
3. Запустите `python tests/selftest.py` и `python -m compileall -q src tests`.
4. Не добавляйте `config.json`, `users.json`, логи, ключи, токены и резервные копии.
5. Описывайте пользовательские изменения по-русски и обновляйте `CHANGELOG.md` перед релизом.
