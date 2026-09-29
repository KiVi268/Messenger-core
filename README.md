# Messenger-core

Общее Rust-ядро клиентов KiVi Messenger: сквозное шифрование поверх [libsignal](https://github.com/signalapp/libsignal) и биндинги для Android (Kotlin) и iOS (Swift) через [UniFFI](https://mozilla.github.io/uniffi-rs/).

- **Лицензия:** AGPL-3.0-only — этого требует libsignal. См. ADR-0001 и ADR-0002 в репозитории Messenger-KiVi.
- **Сервер это ядро не использует** (ADR-0002).
- **Статус:** 0.1 — каркас для сквозного прототипа. Состояние хранится в БД платформы (ADR-0004).

## Структура

```
crates/
├── kivi-crypto/      Ядро: ключи устройства, сессии Signal Protocol (PQXDH), шифрование
├── kivi-ffi/         Тонкий FFI-слой (UniFFI) → Kotlin / Swift
└── uniffi-bindgen/   Генератор биндингов
```

Типы ядра повторяют контракт [messenger-protocol](https://github.com/KiVi268/messenger-protocol) (`kivi.keys.v1`, `kivi.messaging.v1`): клиент перекладывает поля в запросы к серверу один в один.

## Что умеет

`LocalDevice` (в Kotlin/Swift — `KiviDevice`):

| Метод | Для чего |
|-------|----------|
| `create(store, account_id, device_id)` | Создать устройство при регистрации: ключ идентичности, registration ID, подписанный EC-ключ, Kyber-ключ «последней надежды» |
| `open(store)` (в Kotlin/Swift — `openDevice`) | Открыть устройство при следующих запусках; `null`, если устройства нет |
| `device_keys()` | Ключи для `AccountService.Register` |
| `generate_pre_keys(n)`, `generate_kyber_pre_keys(n)` | Одноразовые ключи для `KeysService.UploadPreKeys` |
| `process_bundle(account, bundle)` | Установить сессию по ответу `KeysService.GetPreKeyBundle` |
| `encrypt(account, device, plaintext)` | Зашифровать сообщение для одного устройства → `OutgoingMessage` |
| `decrypt(account, device, kind, content)` | Расшифровать `Envelope` |

## Хранение состояния

Ядро не владеет базой данных (ADR-0004 в Messenger-KiVi). Платформа реализует интерфейс хранилища «ключ → значение» поверх своей зашифрованной БД — Room + SQLCipher на Android, GRDB + SQLCipher на iOS:

```kotlin
interface KiviStore {
    fun load(kind: RecordKind, key: String): ByteArray?
    fun store(kind: RecordKind, key: String, value: ByteArray)
    fun remove(kind: RecordKind, key: String)
}
```

Достаточно одной таблицы `(kind, key) → value`. Виды записей — `RecordKind`: свой аккаунт, сессии, ключи идентичности собеседников, одноразовые и подписанные ключи, отметки использования Kyber-ключа «последней надежды».

- **Синхронные вызовы в потоке вызывающего кода.** Поэтому приём сообщения выполняется в одной транзакции: `decrypt` + запись сообщения в БД, затем фиксация транзакции и только после неё ACK серверу (PRD §7.6.1). Если приложение упадёт до фиксации, откатятся и сообщение, и изменения сессии, а сервер доставит сообщение повторно.
- **`RecordKind.LocalAccount`** содержит приватный ключ идентичности. Платформа дополнительно шифрует эту запись неизвлекаемым ключом из Android Keystore / Secure Enclave (PRD §7.3).
- **Доверие к ключам собеседников** — trust on first use: первый ключ собеседника принимается, смена ключа возвращает `UntrustedIdentity` до подтверждения пользователем.

## Проверено тестами

- Установка сессии и переписка в обе стороны, в том числе без одноразовых ключей, с сообщениями не по порядку.
- Отказ при подделанной подписи ключа, изменённом шифротексте и повторной расшифровке того же сообщения.
- Хранилище: состояние переживает перезапуск, счётчики ID ключей продолжаются, использованные одноразовые ключи удаляются, повторное использование Kyber-ключа «последней надежды» отвергается, смена ключа собеседника не принимается молча, ошибки БД платформы доходят до вызывающего кода.
- **Совместимость sealed sender с сервером без libsignal** (`tests/sealed_sender_server_signing.rs`): сертификаты, подписанные обычным Ed25519, проходят проверку libsignal, если сервер:
  1. публикует свой ключ в форме Curve25519 (u-координата Montgomery), с префиксом `0x05`;
  2. переносит знаковый бит своего Ed25519-ключа в старший бит последнего байта подписи (`signature[63] |= pubkey[31] & 0x80`).

  Значит, сервер может выпускать сертификаты в родном формате libsignal (`sealed_sender.proto`), а клиенты — использовать sealed sender из libsignal без изменений.

- Сборка под Android (`arm64-v8a`, `armeabi-v7a`, `x86_64`, minSdk 26), выравнивание страниц 16 КБ для 64-битных библиотек (требование Google Play).

## Сборка

Нужны Rust (версия фиксируется в `rust-toolchain.toml`) и `protoc` — его использует сборка libsignal.

```sh
# Ubuntu/Debian
sudo apt-get install protobuf-compiler
# macOS
brew install protobuf
```

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

### Android

Нужны Android NDK и [cargo-ndk](https://github.com/bbqsrc/cargo-ndk).

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk

export ANDROID_NDK_HOME=/path/to/ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 --platform 26 \
  -o out/jniLibs build -p kivi-ffi --release

# Kotlin-биндинги (пакет com.kivi.core)
cargo build -p kivi-ffi
cargo run -p uniffi-bindgen -- generate --library target/debug/libkivi_ffi.so \
  --language kotlin --out-dir out/kotlin
```

`out/jniLibs` копируется в `src/main/jniLibs` Android-модуля, `out/kotlin` — в исходники. Биндингам нужна зависимость `net.java.dev.jna:jna` (aar). CI собирает то же самое и публикует как артефакт сборки `kivi-core-android`.

### iOS

Сборка XCFramework — следующий шаг (нужен macOS-раннер). Swift-биндинги уже генерируются:

```sh
cargo run -p uniffi-bindgen -- generate --library target/debug/libkivi_ffi.so \
  --language swift --out-dir out/swift
```

## Ключ идентичности

Общий для всех устройств аккаунта (ADR-0003 в Messenger-KiVi). В `RemoteDeviceBundle` клиент подставляет `identity_public_key` из `GetPreKeyBundleResponse` — он одинаковый для всех устройств собеседника. Передача ключевой пары на привязываемое устройство — следующий шаг.

## Открытые вопросы

- **Подтверждение смены ключа собеседника.** Сейчас смена ключа только блокирует отправку (`UntrustedIdentity`); API для подтверждения пользователем — следующий шаг вместе с экраном safety numbers (EPIC-012).
- **Формат сертификатов sealed sender в messenger-protocol** стоит заменить на формат libsignal — тест выше показывает, что сервер может его выпускать.

## Лицензирование вкладов

Код распространяется под AGPL-3.0-only. Перед приёмом первого внешнего вклада вводится CLA (ADR-0001).
