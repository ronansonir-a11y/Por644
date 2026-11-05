# Ultimate Game RE & Modding Suite 2.0

Набор для разрешённой интероперабельности, офлайн-моддинга и изолированного сохранения игр. Подробности, схемы и ссылки на источники — в [русском руководстве](docs/ULTIMATE_GAME_RE_GUIDE_RU.md).

**Границы:** не применять против действующих коммерческих мультиплеерных сервисов, античита или DRM. Никаких ключей, расшифровки retail SELF и автоматического внедрения нет. Работайте с разрешёнными копиями и резервными копиями. GoldHEN и Android-устройство не проверялись; готового универсального портирования нет.

## Состав

| Файл | Назначение |
|---|---|
| `tools/re_swiss_knife.py` | Самостоятельный Python CLI: анализ, AOB, GoldHEN-кандидат, SELF/NSO и FMF. |
| `docs/ULTIMATE_GAME_RE_GUIDE_RU.md` | Руководство, оговорки и проверенные источники. |
| `templates/goldhen_cheat_sample.json` | Искусственный пример JSON, не чит для настоящей игры. |
| `templates/android_arm64_hook.cpp` | Явно вызываемые своим приложением patch API и 16-байтовый ARM64 jump; не инжектор и не полноценный trampoline. |
| `build/android_arm64/liboffline_patch.so` | Android ARM64 библиотека внутри полного ZIP; не содержит PS4-байтов и не проверена на телефоне. |
| `templates/local_ps4_server_emulator.py` | Синтетический локальный сервер; не протокол PSN или реальной игры. |
| `tests/`, `tools/package_suite.py`, `.github/workflows/` | Тесты, воспроизводимая упаковка и CI. |

## 1. Установка и анализ

Python 3.10+. PowerShell из распакованного каталога:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/re_swiss_knife.py --analyze "D:\Games\MyOfflineGame"
python tools/re_swiss_knife.py --analyze "D:\Copies\game.apk" --json
```

Если PowerShell блокирует активацию, используйте `.venv\Scripts\python.exe`. Linux/macOS: `python3 -m venv .venv`, `source .venv/bin/activate`. Capstone нужен для дизассемблирования и создания AOB; `zstandard` — только для zstd-потоков FMF. Поиск байтов, zlib и raw LZ4 работают без C-расширений.

Распознаются Unity Mono/IL2CPP, Unreal (IoStore **не означает только UE5**), Source, Frostbite, Godot, Ren'Py; ELF/PE/Mach-O/NSO/SELF, признаки CPU и некоторые compiler/packer-маркеры. Вывод эвристический. NSO magic не доказывает CPU; SELF magic не доказывает подлинность и отсутствие шифрования. APK/IPA читаются как ZIP без извлечения и расшифровки.

## 2. AOB и GoldHEN

Создайте **учебный** raw-файл (не настоящая игра):

```powershell
python -c "from pathlib import Path; Path('demo.bin').write_bytes(bytes.fromhex('48 89 C0 E8 11 22 33 44 90 C3'))"
python tools/re_swiss_knife.py --scan-aob demo.bin --arch x86_64 --pattern "48 89 C0 E8 ?? ?? ?? ??" --context 8
python tools/re_swiss_knife.py --make-aob demo.bin --arch x86_64 --offset 0x0 --length 8
python tools/re_swiss_knife.py --generate-patch demo.bin --arch x86_64 --offset 0x0 `
  --off "48 89 C0" --on "90 90 90" --title-id CUSA12345 --version 01.00 `
  --goldhen-offset 0x1000 --out-dir demo-output
python demo-output/offline_file_patcher.py demo.bin --output demo-patched.bin
python demo-output/offline_file_patcher.py demo-patched.bin --undo --output demo-restored.bin
```

Для **валидного PS4 x86-64 ELF64** параметр `--goldhen-offset` теперь можно опустить. CLI проверяет весь патч в единственном file-backed `PT_LOAD` и печатает:

```text
base_vaddr = min(PT_LOAD.p_vaddr)
vaddr = p_vaddr + (file_offset - p_offset)
кандидат = vaddr - base_vaddr
```

Данные и SHA-256 записываются в `patch_metadata.json`; это **не** часть формата GoldHEN. В GoldHEN-каталог копируют только `CUSAXXXXX_01.00.json` (например, `CUSA12345_01.00.json`), обычно в `/data/GoldHEN/cheats/json/`; документация также указывает `/user/data/GoldHEN/cheats/json/` — проверяйте mount.

**Кандидат не подтверждает runtime base, ASLR, версию GoldHEN или совместимость сборки.** Его необходимо независимо проверить на своей консоли. При пересечении сегментов или выходе за file-backed range CLI отказывает; `--goldhen-offset` остаётся ручным override и обязателен для самостоятельно проверенного raw dump. Вместо `--offset` можно использовать уникальный `--aob` и `--match-delta`. CLI проверяет `--off`, но не может доказать происхождение ELF или назначение кода. Никакой опубликованной официальной GoldHEN JSON Schema не найдено: тестируется локальная схема поддерживаемого подмножества.

Для других своих файлов используйте `--generate-patch ... --file-only`: создаётся только копирующий патчер с проверкой SHA-256, без фиктивного PS4 JSON. Исходник и существующий выход не перезаписываются.

## 3. PS4 SELF/FSELF, Switch NSO и FMF

```powershell
python tools/re_swiss_knife.py --unpack-binary "D:\Copies\eboot.bin" --output eboot.elf
python tools/re_swiss_knife.py --unpack-binary "D:\Copies\main.nso" --output main.elf
python tools/re_swiss_knife.py --scan-aob main.elf --arch arm64 --pattern "1F 20 03 D5" --context 8
python tools/re_swiss_knife.py --fmf-info "D:\Mods\skin.fmf" --json
python tools/re_swiss_knife.py --fmf-unpack "D:\Mods\skin.fmf" --output skin-unpacked
python tools/re_swiss_knife.py --fix-mod-case skin-unpacked --dry-run
python tools/re_swiss_knife.py --fix-mod-case skin-unpacked --output skin-lowercase
```

SELF: обрабатываются описанные незашифрованные blocked entries и одиночные zlib-потоки; сегменты восстанавливаются на ELF `p_offset`. Флаг шифрования, повреждение или неподдерживаемый layout дают отказ; retail не расшифровывается. Наличие plaintext не является доказательством подлинности.

NSO0: raw LZ4 декодируется чистым Python, валидируются размеры и заявленные SHA-256; в синтетическом ELF64 сохраняются VA, права и BSS. **ARM64 предполагается, но NSO сам CPU не указывает.** Результат — для сканирования, не гарантия запуска; файловые offset результата отличаются от NSO.

FMF: поддерживаются известные legacy UTF-16/2020-style каталоги, включая zlib/zstd и zstd-каталог с префиксом длины. Неподдерживаемые версии могут не читаться. Если индекс отсутствует, извлекаются только найденные потоки с искусственными именами `stream_...`; `--carve` явно включает такой приблизительный режим для неподдерживаемого индекса. Он не восстанавливает имена или структуру и может пропустить данные. Компрессия не является расшифровкой. В дополнение к синтетическим тестам проверен один открытый FM23-совместимый font-мод: 86 файлов и `config.xml`; это не гарантия поддержки всех FM23/Touch архивов.

`--fix-mod-case` создаёт **новую копию** (по умолчанию соседнюю `имя_lowercase`), не изменяет исходник; обнаруживает коллизии и symlink. В `config.xml` нормализуются явные файловые атрибуты, а `from`/`to` — только когда совпадают с локальным путём/именем файла (в том числе без расширения); неразрешённые виртуальные ID, прочие значения, URL и entity-ссылки сохраняются. Проверяйте результат вручную. Распаковка и восстановление ограничены 1024 МиБ; при необходимости задайте `--max-output-mb N` (1–16384). Существующие выходы не перезаписываются.

## 4. Android ARM64

Шаблон предоставляет `apply_offline_patch`, `encode_arm64_absolute_jump` и `apply_offline_arm64_jump`. Jump: `51 00 00 58` (`LDR X17,#8`), `20 02 1F D6` (`BR X17`), затем 64-битный little-endian адрес. Он занимает 16 байт и портит X17; **не** переносит вытесненные инструкции и не является полным trampoline. Адрес и оригинальные ARM64-байты нужно определить отдельно в собственном процессе.

Патч выравнивает страницы, проверяет ожидаемые байты, меняет permissions, очищает instruction cache и восстанавливает права. По умолчанию действует W^X; `-DOFFLINE_PATCH_ALLOW_RWX` — отдельный небезопасный opt-in, который может отклонить система. `-DOFFLINE_PATCH_ENABLE_CONSTRUCTOR` добавляет пустую точку инициализации, не ставящую патч автоматически. Остановите все затронутые потоки; в случае `-4` байты уже изменены, но права не восстановлены.

```bash
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++" \
  -std=c++17 -O2 -fPIC -shared -fno-exceptions -fno-rtti -nostdlib++ \
  templates/android_arm64_hook.cpp -o liboffline_patch.so
```

Библиотека в проверенном локальном ZIP собрана AArch64 toolchain из зеркала NDK r23b (23.1.7779620), Clang 12, для API 24, её ELF64/ET_DYN/EM_AARCH64 проверены; на Android она не запускалась. Linux CI настроен искать установленный NDK, собирать `build/android_arm64/liboffline_patch.so` через NDK Clang и отказывать, если NDK/ELF-проверка не прошли. Результат конкретного CI запуска следует проверять отдельно.

## 5. Локальный сервер и тесты

```powershell
python templates/local_ps4_server_emulator.py
# В отдельном терминале:
Invoke-RestMethod http://127.0.0.1:8765/health
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

Сервер — собственный синтетический REST/WebSocket/UDP пример, а не backend реальной игры. Для LAN требуется явный RFC1918 IPv4, `--allow-lan` и изоляция. Подробности — в руководстве.

## 6. Архив

Полный `Ultimate_Game_RE_&_Modding_Suite.zip` содержит исходники и библиотеку по пути `build/android_arm64/liboffline_patch.so`. Для пересборки с уже собранной NDK-библиотекой:

```powershell
python tools/package_suite.py --force --android-so build/android_arm64/liboffline_patch.so
python -m zipfile -t 'Ultimate_Game_RE_&_Modding_Suite.zip'
```

Без `--android-so` упаковщик явно создаёт **source-only** архив. В GitHub Actions job `Build Android ARM64 and package suite` требует реальную NDK-сборку и включает её в артефакт `Ultimate_Game_RE_&_Modding_Suite`. Игры, ключи, проприетарные SDK, сертификаты и сохранения в архив не входят.
