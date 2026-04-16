# Fintech Expense & Payment Platform

Модульный монолит: Java 17 / Spring Boot / PostgreSQL / Redis / Kafka

# Зачем нужен этот проект?

Проект был создан в учебных целях

## Запуск

```bash
docker-compose up -d
./mvnw spring-boot:run
```

## Модули

| Модуль              | Ответственность                        |
|---------------------|----------------------------------------|
| auth-module         | Регистрация, JWT RS256, refresh tokens |
| account-module      | Счета, балансы, холды                  |
| limits-module       | Дневные/месячные лимиты                |
| transaction-module  | Переводы, ledger, категории            |
| analytics-module    | Витрины, агрегации, отчёты             |
| notification-module | Уведомления (push, email, in-app)      |
| fraud-module        | Обнаружение подозрительных операций    |
| audit-module        | Неизменяемый лог действий              |
| infrastructure      | Idempotency, outbox, rate limiter      |
