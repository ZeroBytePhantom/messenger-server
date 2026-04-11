
# Secure Messaging Server

Серверное приложение для защищённого обмена сообщениями в автономных и изолированных сетях.

## Возможности

- Аутентификация пользователей (SHA-256 + соль)
- Шифрование данных (AES-256-GCM)
- Центр сертификации (CA)
- Личные и групповые чаты
- Store-and-Forward (оффлайн-доставка)
- Синхронизация сообщений
- SQLite (WAL)

## Сборка

```bash
git clone <repo_url>
cd project
mkdir build && cd build
cmake ..
make -j$(nproc)
```
## Запуск
```bash
./messenger-server --config config.json ```
