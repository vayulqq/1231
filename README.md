# GTK4 Demo — простое GUI приложение на C

Минималистичное десктопное приложение на **GTK4 + C** с двумя виджетами:
- **Counter** — счётчик с кнопками `+`, `−`, `Reset`
- **Greeter** — поле ввода имени и кнопка приветствия

## Структура файлов

```
├── main.c                        # исходный код приложения
├── meson.build                   # сборочный скрипт (Meson)
└── .github/
    └── workflows/
        └── build-windows.yml     # CI/CD: сборка portable-бандла под Windows
```

## Локальная сборка

### Linux / macOS

```bash
# Зависимости (Debian/Ubuntu)
sudo apt install libgtk-4-dev meson ninja-build

# Зависимости (macOS)
brew install gtk4 meson ninja

# Сборка
meson setup builddir --buildtype=release
meson compile -C builddir
./builddir/gtk4-demo
```

### Windows (MSYS2)

```bash
# В терминале MSYS2 MINGW64
pacman -S mingw-w64-x86_64-gtk4 mingw-w64-x86_64-meson mingw-w64-x86_64-ninja

meson setup builddir --buildtype=release --strip
meson compile -C builddir
./builddir/gtk4-demo.exe
```

## CI/CD: GitHub Actions

Workflow-файл `.github/workflows/build-windows.yml` автоматически:

1. Поднимает `windows-latest` runner
2. Устанавливает **MSYS2 + MinGW-w64** с GTK4
3. Компилирует приложение через Meson (Release + LTO + strip)
4. Рекурсивно собирает все нужные **DLL** через `ldd`
5. Копирует runtime-ассеты GTK: pixbuf-loaders, иконки, темы, glib-схемы, локали
6. Упаковывает всё в `gtk4-demo-windows-x64.zip`
7. При пуше тега (`v*`) автоматически создаёт **GitHub Release**

### Запуск вручную

В репозитории: **Actions → Build (Windows, portable bundle) → Run workflow**

### Результат

Скачанный ZIP содержит:
```
gtk4-demo.exe      ← само приложение
*.dll              ← все зависимости
lib/               ← gdk-pixbuf loaders
share/             ← темы, иконки, схемы, локали
run.bat            ← ярлык для запуска
```

Распакуй и запусти `gtk4-demo.exe` (или `run.bat`) — сторонний GTK устанавливать не нужно.

## Заметка о «статической» линковке

GTK4 на Windows **не поддерживает** полную статическую линковку в один `.exe` —
glib, pango, cairo и другие библиотеки требуют DLL из-за особенностей Windows
(глобальные хуки, COM, драйверы шрифтов). Поэтому «статическая сборка» для GTK
на Windows означает именно **portable bundle** (exe + DLL без установки).
