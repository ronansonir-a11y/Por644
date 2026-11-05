# Ultimate Game RE & Modding Suite

Набор для законной интероперабельности, офлайн-моддинга и экспериментов по сохранению игр. Полное [русское руководство](docs/ULTIMATE_GAME_RE_GUIDE_RU.md) содержит ссылки на исследованные GitHub-исходники, схемы памяти, методики для PS4/Android и ограничения.

**Важно:** не использовать против действующих коммерческих мультиплеерных сервисов, античита или DRM. Работайте с разрешёнными копиями и резервными копиями. Ни GoldHEN, ни NDK/телефон, ни конкретные игры здесь не проверялись; готового универсального портирования и обхода защит нет.

## Состав

| Файл | Назначение |
|---|---|
| `tools/re_swiss_knife.py` | Самостоятельный CLI: признаки движков/форматов; AOB поиск/генерация; офлайн-генератор патчей. |
| `docs/ULTIMATE_GAME_RE_GUIDE_RU.md` | Энциклопедия, архитектура, инструкции и источники. |
| `templates/goldhen_cheat_sample.json` | **Искусственный пример**, не готовый чит настоящей игры. |
| `templates/android_arm64_hook.cpp` | Явно вызываемый своим приложением memory-patch API, не инжектор/trampoline. |
| `templates/local_ps4_server_emulator.py` | Синтетический локальный REST/WebSocket/UDP сервер; не протокол PSN или реальной игры. |
| `tests/` | Автотесты и локальная схема выдаваемого подмножества GoldHEN JSON. |
| `tools/package_suite.py`, `.github/workflows/` | Воспроизводимая упаковка и CI. |

## 1. Windows: установка и анализ

Нужен Python 3.10+. В PowerShell из распакованного каталога:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/re_swiss_knife.py --analyze "D:\Games\MyOfflineGame"
python tools/re_swiss_knife.py --analyze "D:\Copies\game.apk" --json
```

Если PowerShell блокирует активацию, используйте `.venv\Scripts\python.exe` вместо `python` без изменения системных политик. На Linux/macOS: `python3 -m venv .venv`, `source .venv/bin/activate` и те же команды. Capstone нужен для генерации сигнатур и дизассемблирования; без него поиск байтов и анализ работают с явным предупреждением.

Распознаются Unity Mono/IL2CPP, Unreal (IoStore **не означает только UE5**), Source, Frostbite, Godot, Ren'Py, признаки возможного custom-движка; ELF/PE/Mach-O/NSO/PS4 SELF/FSELF, заголовки CPU, некоторые compiler/symbol/packer-маркеры. Вывод вероятностный. `cryptid` — признак конкретного Mach-O slice, а не универсальный детектор DRM. NSO magic не доказывает CPU; SELF/FSELF magic не доказывает тип подписи или степень шифрования. APK/IPA читаются как ZIP без распаковки, архивы не дешифруются. См. руководство об ограничениях.

## 2. AOB: безопасный учебный файл

```powershell
python -c "from pathlib import Path; Path('demo.bin').write_bytes(bytes.fromhex('48 89 C0 E8 11 22 33 44 90 C3'))"
python tools/re_swiss_knife.py --scan-aob demo.bin --arch x86_64 --pattern "48 89 C0 E8 ?? ?? ?? ??" --context 8
python tools/re_swiss_knife.py --make-aob demo.bin --arch x86_64 --offset 0x0 --length 8
```

`--scan-aob` печатает все совпадения; `--max-matches 100` ограничит вывод, `--context 0` выключит дизассемблирование. `--make-aob` требует известную границу инструкции; x86 относительные ветви и memory displacement маскируются, ARM64-инструкции со смешанными смещениями могут целиком становиться wildcard. Проверяйте уникальность в каждой версии и реальное назначение кода.

**File offset, RVA и runtime address — разные величины.** RVA печатается только для однозначного отображения по заголовкам ELF/PE/Mach-O; это не адрес запущенного процесса и не подтверждённый GoldHEN offset. Для SELF/NSO/fat Mach-O автоматического преобразования нет.

## 3. PS4 Pro + GoldHEN: генерация (только офлайн)

Следующая команда использует **синтетический `demo.bin` из предыдущего раздела**. Полученный JSON не является читом для реальной игры; `CUSA12345` и offset вымышлены:

```powershell
python tools/re_swiss_knife.py --generate-patch demo.bin --arch x86_64 --offset 0x0 `
  --off "48 89 C0" --on "90 90 90" --title-id CUSA12345 --version 01.00 `
  --goldhen-offset 0x1000 --out-dir demo-output
python demo-output/offline_file_patcher.py demo.bin --output demo-patched.bin
python demo-output/offline_file_patcher.py demo-patched.bin --undo --output demo-restored.bin
```

Для настоящего разрешённого офлайн-эксперимента нужны точный PS4 x86-64 ELF или самостоятельно проверенный raw dump (не зашифрованный SELF), CUSA/версия/модуль, оригинальные байты и **отдельно установленный** GoldHEN memory offset. CLI проверяет `--off` и не выбирает неоднозначный `--aob`, но самостоятельно не проверяет происхождение ELF или offset в памяти консоли. Установка JSON на своей консоли: обычно `/data/GoldHEN/cheats/json/`; документация меню также указывает `/user/data/GoldHEN/cheats/json/` — проверяйте mount и версию GoldHEN. См. руководство и источники.

В upstream не найдена опубликованная формальная JSON Schema. Тесты строго валидируют **локальную схему поддерживаемого подмножества**, сверенную с реальными JSON и кодом менеджера; это не доказательство совместимости всех вариантов GoldHEN или работоспособности на PS4.

Для любого другого собственного офлайн-файла используйте `--file-only`: требуется `--offset` или `--aob`, а также `--off`, `--on`, `--out-dir`; создаётся только копирующий файл-патчер, без фиктивного PS4 JSON. Например, на том же учебном `demo.bin`:

```powershell
python tools/re_swiss_knife.py --generate-patch demo.bin --file-only --offset 0x8 --off "90 C3" --on "90 90" --out-dir file-demo
python file-demo/offline_file_patcher.py demo.bin --output demo-file-patched.bin
```

Патчер проверяет SHA-256 и байты, создаёт только новый файл и поддерживает `--undo`. Он не сохраняет подписи/целостность защищённых пакетов.

## 4. Honor X8c / Android ARM64

`android_patch_template.cpp` компилируется NDK для `arm64-v8a`, не содержит PS4/x86 байтов и не внедряется в чужой процесс. Приложение-владелец должно само вызвать API с отдельно проверенными ARM64 адресом/байтами и permissions. Нужны остановка затронутых потоков, корректные границы страниц, W^X и очистка instruction cache; см. комментарии шаблона и руководство. Шаблон компилировался и проверялся на host, но **не** на телефоне или Android NDK.

```bash
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++" \
  -std=c++17 -fPIC -shared templates/android_arm64_hook.cpp -o liboffline_patch.so
```

На Windows используйте соответствующий путь `prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang++.cmd`. Turnip/Vulkan и перенос OpenOrbis зависят от конкретного драйвера, ABI и приложения; прямое выполнение PC/PS4-бинарника не обещается.

## 5. Локальный сервер сохранения

```powershell
python templates/local_ps4_server_emulator.py
# В отдельном терминале:
Invoke-RestMethod http://127.0.0.1:8765/health
Invoke-RestMethod -Method Post -ContentType 'application/json' -Body '{"type":"move","seq":1,"dx":1,"dy":0}' -Uri http://127.0.0.1:8765/input
```

Демонстрация также поддерживает `ws://127.0.0.1:8765/ws` и UDP `127.0.0.1:8766`; примеры клиентов — в руководстве. На LAN нужно явно указать конкретный RFC1918 IPv4, например `--bind 192.168.1.20 --allow-lan`, и изолировать сеть/firewall. Нет TLS, аккаунтов или сохранения состояния. Для подключения собственного клиента необходимо реализовать свой совместимый протокол; retail-игры не заработают с этим скелетом автоматически.

## 6. Тесты и архив

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tools/package_suite.py
```

Архив `Ultimate_Game_RE_&_Modding_Suite.zip` создаётся в корне. Повторная сборка: `python tools/package_suite.py --force`; файл не будет заменён без явного флага. В GitHub Actions после успешных тестов на Linux/Windows откройте job `Package suite` и скачайте артефакт `Ultimate_Game_RE_&_Modding_Suite`; контейнер GitHub может содержать внутри ещё один одноимённый ZIP. Никакие игры, ключи, проприетарные SDK, сертификаты и сохранения в набор не входят.
