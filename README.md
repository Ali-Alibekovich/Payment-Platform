# Fintech Expense & Payment Platform

Модульный монолит: Java 21 / Spring Boot 3.4 / PostgreSQL / Redis / Kafka

## Запуск

```bash
docker-compose up -d
./mvnw spring-boot:run -pl auth-module
```

## Статус модулей

| Статус | Модуль                | Прогресс          | Ответственность                        |
|:------:|-----------------------|-------------------|----------------------------------------|
|   ✅    | `auth-common`         | `██████████` 100% | Shared JWT-валидация, автоконфигурация |
|   ✅    | `auth-module`         | `██████████` 100% | Регистрация, JWT HS256, refresh, роли  |
|   📋   | `account-module`      | `░░░░░░░░░░`   0% | Счета, балансы, холды                  |
|   📋   | `limits-module`       | `░░░░░░░░░░`   0% | Дневные/месячные лимиты                |
|   📋   | `transaction-module`  | `░░░░░░░░░░`   0% | Переводы, ledger, категории            |
|   📋   | `analytics-module`    | `░░░░░░░░░░`   0% | Витрины, агрегации, отчёты             |
|   📋   | `notification-module` | `░░░░░░░░░░`   0% | Уведомления (push, email, in-app)      |
|   📋   | `fraud-module`        | `░░░░░░░░░░`   0% | Обнаружение подозрительных операций    |
|   📋   | `audit-module`        | `░░░░░░░░░░`   0% | Неизменяемый лог действий              |
|   📋   | `infrastructure`      | `░░░░░░░░░░`   0% | Idempotency, outbox, rate limiter      |

**Легенда:** ✅ Готов &nbsp;·&nbsp; 🚧 В разработке &nbsp;·&nbsp; 📋 Запланирован

**Rate limiting** для публичных эндпоинтов (в т.ч. `/auth`) планируется отдельным модулем или edge-слоем и подключается
к сервисам после появления — в `auth-module` не встроен.
