# AGENTS

## Purpose

This document describes every logical **agent** (a narrowly scoped, testable responsibility center) that makes up the SecureChat system.  Thinking in agents clarifies the threat‑model, simplifies onboarding, and maps cleanly onto micro‑frontends and micro‑services.

---

## Directory Map

```
├── apps/web                # Next.js front‑end (UIAgent, CryptoAgent)
├── packages/server         # tRPC backend (AuthAgent, MessageRouter, StorageAgent, RealtimeAgent)
├── packages/infra          # IaC, Docker, CI, monitoring (MonitoringAgent)
└── packages/shared         # type‑safe DTOs, protobuf schemas
```

---

## Agent Catalogue

| Agent               | Runtime                                  | Main entry                     | Core responsibility                                                      | Security invariants                                             |
| ------------------- | ---------------------------------------- | ------------------------------ | ------------------------------------------------------------------------ | --------------------------------------------------------------- |
| **AuthAgent**       | Server (Node)                            | `server/auth/index.ts`         | LDAP bind (GLAuth), issues/rotates JWT, tracks devices                   | Passwords never stored. JWT TTL ≤ 15 min. IP + DN rate‑limited. |
| **CryptoAgent**     | Client (WebWorker / React‑Native thread) | `web/workers/crypto.worker.ts` | Generates X3DH pre‑keys, maintains Double‑Ratchet state, local key‑vault | Private keys never leave worker; memory zeroised after use.     |
| **MessageRouter**   | Server                                   | `server/routes/message.ts`     | Ingests ciphertext payloads, persists, forwards via WS/SSE               | Validates quota; server cannot read plaintext.                  |
| **StorageAgent**    | Server                                   | Prisma ORM                     | Persists users, contacts, devices, sessions, messages                    | Enforces row‑level ACL; audited writes.                         |
| **RealtimeAgent**   | Server                                   | `server/realtime/socket.ts`    | WebSocket hub (socket.io) with Redis adapter; fallback SSE               | JWT verified at connect. No broadcast leakage.                  |
| **PushAgent**       | Server (future)                          | `server/push/index.ts`         | Stores VOIP/FCM tokens, sends encrypted push notifications               | Encrypts payload; stores only deviceId + token.                 |
| **UIAgent**         | Client                                   | React component tree           | Renders chats/contacts; indicates encryption status                      | Reads only decrypted plaintext in memory.                       |
| **MonitoringAgent** | Server                                   | `infra/otel.ts`                | OpenTelemetry traces, Prom‑metrics, Sentry errors                        | Scrubs PII before export.                                       |

---

## Interaction Flow (first message A ▶ B)

1. **UIAgent** ▶ `POST /api/messages` with `{ header, ciphertext }`.
2. **AuthAgent** middleware attaches `req.userId` after verifying JWT.
3. **MessageRouter**

   1. validates header (ratchet step, recipient devices)
   2. persists row in `Message` table via **StorageAgent**
   3. emits `msg` through **RealtimeAgent** to every online device of B.
4. On each recipient device **CryptoAgent** derives new ratchet key, decrypts, hands plaintext to **UIAgent**.

---

## Yarovaya Compliance Notes (RF)

* Провайдеру доступен лишь TLS‑трафик; контент «нечитаем» благодаря клиентскому E2E‑шифрованию.
* Серверы держат **только** публичные ключи и ciphertext; приватные ключи хранятся на клиенте (IndexedDB / Android Keystore).
* После использования ключевой материал затирается (`libsodium_memzero`).
* Логи LDAP ограничены DN + timestamp без пароля.

---

## TODO per Agent

| Agent               | Next milestones                                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **AuthAgent**       | • Refresh‑token rotation & blacklist<br>• Optional WebAuthn MFA<br>• IP+DN adaptive rate‑limiting                       |
| **CryptoAgent**     | • Rotate `signedPreKey` every 30 дней<br>• GC consumed one‑time pre‑keys<br>• QR‑код «device link» с SAS‑подтверждением |
| **MessageRouter**   | • Шифрованные вложения (streaming AEAD, S3‑compatible store)<br>• Anti‑spam per‑user quotas                             |
| **StorageAgent**    | • Row‑level шифрование push‑токенов (AES‑SIVDet)<br>• Soft‑delete & TTL retention policy                                |
| **RealtimeAgent**   | • Presence heartbeat + offline queue drain<br>• HTTP/3 QUIC fallback                                                    |
| **PushAgent**       | • WebPush (VAPID) + FCM data payloads<br>• Payload sealing via per‑device key                                           |
| **UIAgent**         | • UI для резервной фразы (Base58 seed) экспорт/импорт<br>• Client‑side full‑text search (FlexSearch)                    |
| **MonitoringAgent** | • Grafana dashboard JSON bundle<br>• Alert: WS error rate >1 % for 5 min                                                |
