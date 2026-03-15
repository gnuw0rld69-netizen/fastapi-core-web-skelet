# Production-Ready Core Skelet for  Web/API Apps built with FastAPI, JWT, MariaDB, and Redis

## Features

- JWT access and refresh tokens
- Login by email only (case-insensitive)
- Email verification and resend flow
- TOTP-based 2FA (setup, enable, disable)
- Role-based access control (admin and superuser policies)
- Redis-backed cache for user lookups
- Redis-backed audit log queue
- Audit logging for auth and user actions
- Security headers and configurable CORS
- Per-user IP/network allowlist for authenticated requests
- Health check endpoint
- Docker support and Alembic migrations

## Tech Stack

- FastAPI
- SQLAlchemy + MariaDB
- Alembic
- Redis
- PyOTP, bcrypt, python-jose
- Docker

## Project Structure

```
app/
  app.py
  core/
  routers/
  services/
  models/
  schemas/
modules/
  cms_module/
alembic/
  env.py
  versions/
Dockerfile
docker-compose.yml
requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and adjust values.

### Database

- `DB_ROOT_PASSWORD` (used by Docker Compose MariaDB)
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`

### JWT

- `SECRET_KEY`
- `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `REFRESH_TOKEN_EXPIRE_DAYS`

### Redis

- `REDIS_HOST`
- `REDIS_PORT`
- `REDIS_DB`
- `REDIS_PASSWORD`
- `REDIS_USE_SSL`

### App

- `PROJECT_NAME`
- `VERSION`
- `BACKEND_BASE_URL`
- `DEBUG`
- `AUTO_CREATE_TABLES`
- `CORS_ORIGINS`

### Access Control

- `TRUSTED_PROXY_IPS`


### Cache

- `CACHE_TTL_SECONDS`

### Turnstile

- `TURNSTILE_SITE_KEY`
- `TURNSTILE_SECRET_KEY`

### Email

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`
- `SMTP_FROM_NAME`
- `SMTP_USE_TLS`
- `SMTP_USE_SSL`
- `SMTP_TIMEOUT_SECONDS`

## Quickstart

### Local

1. `python -m venv venv && source venv/bin/activate`
2. `pip install -r requirements.txt`
3. `cp .env.example .env` and update values
4. Start MariaDB and Redis (or use Docker Compose)
5. `uvicorn app.app:app --reload`

### Docker

`docker-compose up --build`

## API Docs

- Swagger UI: `http://localhost:8000/api/v1/docs`
- ReDoc: `http://localhost:8000/api/v1/redoc`

## Web Interface

- Users (RU): `http://localhost:8000/ru/users/`
- Users (EN): `http://localhost:8000/en/users/`
- Auth: `/{lang}/users/auth`
- Register: `/{lang}/users/register`
- Verify email: `/{lang}/users/verify`
- Reset password: `/{lang}/users/reset`
- Profile: `/{lang}/users/profile`
- Admin panel: `/{lang}/admin_panel/`

## Modules

Modules are loaded automatically from the `/modules` directory. Each module provides its own routes,
templates, and database tables (prefixed with the module name).

Module manifests drive dynamic admin UI entries in `/admin_panel` and define the module's routers,
templates directory, and metadata for table creation.

Each module also ships its own translations under `modules/<module>/i18n/`.

### CMS Module

- Admin UI: `/{lang}/admin_panel/module_cms_module`
- Pages: `/{lang}/pages/{slug}`
- Root page: if a published CMS page is marked as root for a language, it can replace `/`.

Access levels:

- `public`: visible to everyone
- `auth`: visible only to authenticated and verified users
- `role`: visible only to moderator/admin/superuser as configured

## Authentication

- Login requires an email address. Emails are normalized to lowercase to prevent duplicates.
- Web login uses a two-step flow when 2FA is enabled: password first, OTP step second.
- In Swagger "Authorize", you can place the OTP in `client_secret` (or `secret_code`) when 2FA is enabled.
- Password reset generates a temporary password and sends it by email.
- Unverified users can sign in but are limited to the profile verification block until email verification is complete.
- 2FA setup renders a QR code plus the secret for manual entry.

## IP Allowlist

If a user has at least one allowlist entry, all authenticated requests must come from an allowed IP or CIDR network.
Manage entries via:

- `GET /api/v1/users/me/allowed-ips`
- `POST /api/v1/users/me/allowed-ips`
- `PUT /api/v1/users/me/allowed-ips/{entry_id}`
- `DELETE /api/v1/users/me/allowed-ips/{entry_id}`

Admin management:

- `GET /api/v1/users/{user_id}/allowed-ips`
- `POST /api/v1/users/{user_id}/allowed-ips`
- `PUT /api/v1/users/{user_id}/allowed-ips/{entry_id}`
- `DELETE /api/v1/users/{user_id}/allowed-ips/{entry_id}`

## Admin Actions

- `POST /api/v1/users/{user_id}/verify-email`
- `POST /api/v1/users/{user_id}/2fa/disable`

## Redis Usage

- User cache is stored under `cache:user:<id>` with TTL from `CACHE_TTL_SECONDS`
- Audit log entries are enqueued in Redis and persisted to MariaDB by the app worker thread

## Alembic Migrations

Ensure `.env` contains the database settings and `SECRET_KEY` before running Alembic.

Create a new migration:

```bash
alembic revision --autogenerate -m "add user tables"
```

Apply migrations:

```bash
alembic upgrade head
```

## Health Check

`GET /health` returns service and database status.
