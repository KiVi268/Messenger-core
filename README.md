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
| `generate(store)` | Шаг 1 регистрации: ключ идентичности, registration ID, подписанный EC-ключ, Kyber-ключ «последней надежды» — без адреса |
| `set_address(account_id, device_id)` | Шаг 2 регистрации: адрес из `RegisterResponse`. До него шифрование возвращает `NotRegistered` |
| `create(store, account_id, device_id)` | `generate` + `set_address`, когда адрес известен заранее (тесты, привязка устройства) |
| `address()` | Адрес устройства или `null`, если регистрация не завершена |
| `open(store)` (в Kotlin/Swift — `openDevice`) | Открыть устройство при следующих запусках; `null`, если устройства нет |
| `device_keys()` | Ключи для `AccountService.Register` |
| `generate_pre_keys(n)`, `generate_kyber_pre_keys(n)` | Одноразовые ключи для `KeysService.UploadPreKeys` |
| `process_bundle(account, bundle)` | Установить сессию по ответу `KeysService.GetPreKeyBundle` |
| `encrypt(account, device, plaintext)` | Зашифровать сообщение для одного устройства → `OutgoingMessage` |
| `decrypt(account, device, kind, content)` | Расшифровать `Envelope` |
| `remote_registration_id(account, device)` | Registration ID собеседника из сессии → `OutgoingMessage.destination_registration_id` |
| `sealed_sender_encrypt(account, device, certificate, plaintext)` | Sealed sender: сервер не узнаёт отправителя. `certificate` — от `CertificateService.GetSenderCertificate` |
| `sealed_sender_decrypt(ciphertext, trust_root, timestamp_ms)` | Расшифровать конверт `ENVELOPE_TYPE_UNIDENTIFIED_SENDER`: отправитель — из сертификата, проверенного по trust root на момент приёма сервером |
| `identity_status(account)` | Состояние ключа собеседника: `Unknown`, `Trusted`, `Verified` или `Changed` (ключ сменился, отправка заблокирована) |
| `trust_identity(account)` | Принять новый ключ собеседника после смены |
| `set_verified(account, verified)` | Отметить ключ проверенным (номер безопасности сверен) или снять отметку |
| `safety_number(account)` | Номер безопасности: 60 цифр и данные для QR-кода; `null`, если ключ собеседника неизвестен |
| `compare_safety_number(account, scanned)` | Сравнить QR-код с экрана собеседника со своим номером |

Функции:

| Функция | Для чего |
|---------|----------|
| `generate_profile_key()` | Profile key аккаунта (32 байта), создаётся при регистрации |
| `unidentified_access_key(profile_key)` | UAK (16 байт) = `HMAC-SHA256(profile_key, "KiVi unidentified access key v1")[0..16]` — для `RegisterRequest` и запросов sealed sender к собеседнику |

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
- **Доверие к ключам собеседников** — trust on first use: первый ключ собеседника принимается. Ключ общий на аккаунт (ADR-0003), поэтому новое устройство собеседника предупреждения не вызывает: его ключи подписаны тем же ключом. Смена ключа (переустановка, перерегистрация):
  - **приём не блокируется** — новый ключ сохраняется (`RemoteIdentity`), сообщение расшифровывается;
  - **отправка блокируется** — `UntrustedIdentity`, пока пользователь не примет новый ключ (`trust_identity`; принятый ключ — `TrustedIdentity`);
  - сессии со старым ключом сбрасываются: `has_session` возвращает `false`, клиент устанавливает новые по ключам с сервера;
  - ключ из `GetPreKeyBundle` запоминается, только если подписи ключей устройства сходятся, — иначе `Protocol`.
- **Номер безопасности** — как у Signal: fingerprint версии 2 (UUID аккаунтов, 5200 итераций SHA-512). Отметка «проверено» (`VerifiedIdentity`) относится к конкретному ключу и не переносится на новый.

## Проверено тестами

- Установка сессии и переписка в обе стороны, в том числе без одноразовых ключей, с сообщениями не по порядку.
- Отказ при подделанной подписи ключа, изменённом шифротексте и повторной расшифровке того же сообщения.
- Хранилище: состояние переживает перезапуск, счётчики ID ключей продолжаются, использованные одноразовые ключи удаляются, повторное использование Kyber-ключа «последней надежды» отвергается, смена ключа собеседника не принимается молча, ошибки БД платформы доходят до вызывающего кода.
- **Совместимость sealed sender с сервером без libsignal** (`tests/sealed_sender_server_signing.rs`): сертификаты, подписанные обычным Ed25519, проходят проверку libsignal, если сервер:
  1. публикует свой ключ в форме Curve25519 (u-координата Montgomery), с префиксом `0x05`;
  2. переносит знаковый бит своего Ed25519-ключа в старший бит последнего байта подписи (`signature[63] |= pubkey[31] & 0x80`).

  Значит, сервер может выпускать сертификаты в родном формате libsignal (`sealed_sender.proto`), а клиенты — использовать sealed sender из libsignal без изменений.
- **Смена ключа и номера безопасности** (`tests/identity.rs`): у обоих собеседников один номер и QR-коды сходятся; при смене ключа сообщение от собеседника принимается, отправка ждёт подтверждения, после `trust_identity` переписка продолжается; отметка «проверено» не переносится на новый ключ; подделанные ключи с сервера не заменяют ключ собеседника; записи, сохранённые до появления `TrustedIdentity`, тоже ловят смену ключа.
- **Sealed sender целиком** (`tests/sealed_sender.rs`): первое сообщение (с установкой сессии) и ответ собеседника через sealed sender с сертификатами, подписанными «как на сервере»; отказ при чужом trust root, истёкшем сертификате, сертификате чужого устройства и подменённом ключе идентичности.

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

## Лицензирование вкладов

Код распространяется под AGPL-3.0-only. Перед приёмом первого внешнего вклада вводится CLA (ADR-0001).
