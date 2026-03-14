from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import base64
import io

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import get_client_ip
from app.core.security import InvalidTokenError, decode_token, verify_password
from app.models.user import User, UserRole
from app.schemas.user import PasswordChangeRequest, UserCreate, UserUpdate
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.services.turnstile_service import TurnstileService
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService
from app.web.i18n import get_translations, normalize_lang

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/{lang}/users", tags=["Web Users"])

PENDING_2FA_COOKIE = "pending_2fa"
PENDING_2FA_TTL_SECONDS = 600


def _get_current_user_from_cookie(
    request: Request,
    db: Session,
    require_verified: bool = True,
) -> User | None:
    token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if not token:
        return None
    try:
        payload = decode_token(token)
    except InvalidTokenError:
        payload = None
        if refresh_token:
            new_access = AuthService.refresh_access_token(db, refresh_token)
            if new_access:
                request.state.new_access_token = new_access
                try:
                    payload = decode_token(new_access)
                except InvalidTokenError:
                    payload = None
        if payload is None:
            return None

    if payload.get("type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    try:
        user_id_int = int(str(user_id))
    except (TypeError, ValueError):
        return None

    user = UserService.get_by_id(db, user_id_int)
    if not user or not user.is_active:
        return None
    if require_verified and not user.is_verified:
        return None

    client_ip = get_client_ip(request)
    if not UserIpAllowlistService.is_ip_allowed(db, user.id, client_ip):
        return None
    return user


def _create_two_factor_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(seconds=PENDING_2FA_TTL_SECONDS)
    payload = {
        "sub": str(user_id),
        "type": "two_factor",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _get_pending_two_factor_user(request: Request, db: Session) -> User | None:
    token = request.cookies.get(PENDING_2FA_COOKIE)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except InvalidTokenError:
        return None
    if payload.get("type") != "two_factor":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    try:
        user_id_int = int(str(user_id))
    except (TypeError, ValueError):
        return None
    user = UserService.get_by_id(db, user_id_int)
    if not user or not user.is_active:
        return None
    if not user.is_two_factor_enabled:
        return None
    return user


def _generate_qr_code_data_uri(data: str) -> str:
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _redirect_with_message(lang: str, path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"/{lang}{path}?message={message}", status_code=status.HTTP_303_SEE_OTHER)


def _lang_path(lang: str, path: str) -> str:
    return f"/{lang}{path}"


def _msg(lang: str, key: str, fallback: str) -> str:
    return get_translations(lang).get(key, fallback)


def _redirect_if_unverified(user: User | None, lang: str) -> RedirectResponse | None:
    if user and not user.is_verified:
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
        )
    return None


def _is_admin_link_visible(user: User | None) -> bool:
    if not user:
        return False
    return user.role in {UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPERUSER}


@router.get("/", response_class=HTMLResponse)
def users_home(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        redirect = _redirect_if_unverified(user, lang)
        if redirect:
            return redirect
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/home.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.get("/auth", response_class=HTMLResponse)
def users_auth_page(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if user:
            message_key = "web.msg.already_authenticated"
            message_fallback = "You are already authenticated"
            if not user.is_verified:
                message_key = "web.msg.email_not_verified"
                message_fallback = "Email is not verified"
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, message_key, message_fallback),
            )
        pending_user = _get_pending_two_factor_user(request, db)
        otp_step = request.query_params.get("step") == "otp" and pending_user is not None
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/login.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "otp_step": otp_step,
                "turnstile_site_key": settings.TURNSTILE_SITE_KEY,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.get("/register", response_class=HTMLResponse)
def users_register_page(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if user:
            message_key = "web.msg.already_authenticated"
            message_fallback = "You are already authenticated"
            if not user.is_verified:
                message_key = "web.msg.email_not_verified"
                message_fallback = "Email is not verified"
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, message_key, message_fallback),
            )
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/register.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "show_admin_link": _is_admin_link_visible(user),
                "already_authenticated": bool(user),
            },
        )
    finally:
        db.close()


@router.get("/reset", response_class=HTMLResponse)
def users_reset_page(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        redirect = _redirect_if_unverified(user, lang)
        if redirect:
            return redirect
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/reset.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "turnstile_site_key": settings.TURNSTILE_SITE_KEY,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.get("/verify", response_class=HTMLResponse)
def users_verify_page(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/verify.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.get("/profile", response_class=HTMLResponse)
def users_profile_page(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.login_required", "Please login first"),
            )
        allowlist_entries = UserIpAllowlistService.list_for_user(db, user.id)
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "users/profile.html",
            {
                "request": request,
                "message": message,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "allowlist_entries": allowlist_entries,
                "two_factor_setup": None,
                "verification_required": not user.is_verified,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.post("/auth/login")
def users_login(
    request: Request,
    lang: str,
    email: str = Form(...),
    password: str = Form(...),
    turnstile_response: str | None = Form(default=None, alias="cf-turnstile-response"),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        redirect = _redirect_if_unverified(user, lang)
        if redirect:
            return redirect
        if not TurnstileService.verify(turnstile_response, get_client_ip(request)):
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "captcha.required", "Captcha required"),
            )
        try:
            normalized_email = validate_email(email).email
        except EmailNotValidError:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.email_required", "Email is required for login"),
            )

        user = AuthService.authenticate_user(db, normalized_email, password)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.invalid_credentials", "Incorrect email or password"),
            )
        if not user.is_active:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.inactive_user", "Inactive user"),
            )
        if user.is_two_factor_enabled:
            pending_token = _create_two_factor_token(user.id)
            message = _msg(lang, "web.msg.otp_required", "2FA code required")
            response = RedirectResponse(
                f"/{lang}/users/auth?message={message}&step=otp",
                status_code=status.HTTP_303_SEE_OTHER,
            )
            response.set_cookie(
                PENDING_2FA_COOKIE,
                pending_token,
                httponly=True,
                samesite="lax",
                max_age=PENDING_2FA_TTL_SECONDS,
            )
            return response

        UserService.update_last_login(db, user)
        tokens = AuthService.create_tokens(user)
        message_key = "web.msg.logged_in"
        message_fallback = "Logged in"
        if not user.is_verified:
            message_key = "web.msg.email_not_verified"
            message_fallback = "Email is not verified"
        response = _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, message_key, message_fallback),
        )
        max_age = settings.WEB_SESSION_HOURS * 60 * 60
        response.set_cookie("access_token", tokens.access_token, httponly=True, samesite="lax", max_age=max_age)
        response.set_cookie("refresh_token", tokens.refresh_token, httponly=True, samesite="lax", max_age=max_age)
        response.delete_cookie(PENDING_2FA_COOKIE)
        return response
    finally:
        db.close()


@router.post("/auth/logout")
def users_logout(lang: str):
    lang = normalize_lang(lang)
    response = _redirect_with_message(
        lang,
        "/users/auth",
        _msg(lang, "web.msg.logged_out", "Logged out"),
    )
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie(PENDING_2FA_COOKIE)
    return response


@router.post("/auth/otp")
def users_login_otp(request: Request, lang: str, otp_code: str = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_pending_two_factor_user(request, db)
        if not user:
            response = _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.otp_session_missing", "2FA session expired"),
            )
            response.delete_cookie(PENDING_2FA_COOKIE)
            return response
        if not AuthService.verify_two_factor_code(user, otp_code):
            message = _msg(lang, "web.msg.invalid_otp", "Invalid 2FA code")
            return RedirectResponse(
                f"/{lang}/users/auth?message={message}&step=otp",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        UserService.update_last_login(db, user)
        tokens = AuthService.create_tokens(user)
        message_key = "web.msg.logged_in"
        message_fallback = "Logged in"
        if not user.is_verified:
            message_key = "web.msg.email_not_verified"
            message_fallback = "Email is not verified"
        response = _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, message_key, message_fallback),
        )
        max_age = settings.WEB_SESSION_HOURS * 60 * 60
        response.set_cookie("access_token", tokens.access_token, httponly=True, samesite="lax", max_age=max_age)
        response.set_cookie("refresh_token", tokens.refresh_token, httponly=True, samesite="lax", max_age=max_age)
        response.delete_cookie(PENDING_2FA_COOKIE)
        return response
    finally:
        db.close()


@router.post("/auth/refresh")
def users_refresh(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            response = _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.refresh_missing", "Refresh token missing"),
            )
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return response
        new_access = AuthService.refresh_access_token(db, refresh_token)
        if not new_access:
            response = _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.refresh_invalid", "Refresh token invalid"),
            )
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return response
        response = _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.token_refreshed", "Token refreshed"),
        )
        max_age = settings.WEB_SESSION_HOURS * 60 * 60
        response.set_cookie("access_token", new_access, httponly=True, samesite="lax", max_age=max_age)
        return response
    finally:
        db.close()


@router.post("/register")
def users_register(
    request: Request,
    lang: str,
    email: str = Form(...),
    username: str = Form(...),
    full_name: str | None = Form(default=None),
    password: str = Form(...),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if user:
            return _redirect_with_message(
                lang,
                "/users/register",
                _msg(lang, "web.msg.already_authenticated", "You are already authenticated"),
            )
        try:
            payload = UserCreate(email=email, username=username, full_name=full_name, password=password)
        except Exception as exc:
            return _redirect_with_message(lang, "/users/register", str(exc))
        try:
            created_user = UserService.create_user(db, payload)
        except ValueError as exc:
            return _redirect_with_message(lang, "/users/register", str(exc))

        token = AuthService.generate_email_verification_token(created_user)
        db.add(created_user)
        db.commit()
        verification_link = AuthService.build_email_verification_link(token)
        subject, text_body, html_body = EmailService.build_verification_email(verification_link)
        EmailService.send_email(created_user.email, subject, text_body, html_body)
        return _redirect_with_message(
            lang,
            "/users/auth",
            _msg(lang, "web.msg.registration_success", "Registration successful. Check your email"),
        )
    finally:
        db.close()


@router.post("/register/resend-verification")
def users_resend_verification(lang: str, email: str = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = UserService.get_by_email(db, email)
        if user and not user.is_verified:
            token = AuthService.generate_email_verification_token(user)
            db.add(user)
            db.commit()
            verification_link = AuthService.build_email_verification_link(token)
            subject, text_body, html_body = EmailService.build_verification_email(verification_link)
            EmailService.send_email(user.email, subject, text_body, html_body)
        return _redirect_with_message(
            lang,
            "/users/verify",
            _msg(lang, "web.msg.verification_sent", "If your account exists, a verification email was sent"),
        )
    finally:
        db.close()


@router.post("/register/verify-email")
def users_verify_email(request: Request, lang: str, token: str = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        verified_user = AuthService.verify_email_token(db, token)
        if not verified_user:
            return _redirect_with_message(
                lang,
                "/users/verify",
                _msg(lang, "web.msg.verification_invalid", "Invalid or expired verification token"),
            )
        current_user = _get_current_user_from_cookie(request, db, require_verified=False)
        if current_user:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_verified", "Email verified successfully"),
            )
        return _redirect_with_message(
            lang,
            "/users/auth",
            _msg(lang, "web.msg.email_verified", "Email verified successfully"),
        )
    finally:
        db.close()


@router.post("/reset-password")
def users_reset_password(
    request: Request,
    lang: str,
    email: str = Form(...),
    turnstile_response: str | None = Form(default=None, alias="cf-turnstile-response"),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not TurnstileService.verify(turnstile_response, get_client_ip(request)):
            return _redirect_with_message(
                lang,
                "/users/reset",
                _msg(lang, "captcha.required", "Captcha required"),
            )
        result = UserService.reset_password_by_email(db, email)
        if result:
            user, new_password = result
            subject, text_body, html_body = EmailService.build_password_reset_email(new_password)
            EmailService.send_email(user.email, subject, text_body, html_body)
        return _redirect_with_message(
            lang,
            "/users/reset",
            _msg(lang, "web.msg.reset_sent", "If your account exists, a new password was sent"),
        )
    finally:
        db.close()


@router.post("/profile/update")
def users_update_profile(
    request: Request,
    lang: str,
    email: str | None = Form(default=None),
    full_name: str | None = Form(default=None),
    password: str | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        try:
            payload = UserUpdate(email=email or None, full_name=full_name or None, password=password or None)
        except Exception as exc:
            return _redirect_with_message(lang, "/users/profile", str(exc))
        try:
            updated = UserService.update_user(db, user.id, payload)
        except ValueError as exc:
            return _redirect_with_message(lang, "/users/profile", str(exc))
        if not updated:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.profile_updated", "Profile updated"),
        )
    finally:
        db.close()


@router.post("/profile/password")
def users_change_password(
    request: Request,
    lang: str,
    current_password: str = Form(...),
    new_password: str = Form(...),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        try:
            payload = PasswordChangeRequest(current_password=current_password, new_password=new_password)
        except Exception as exc:
            return _redirect_with_message(lang, "/users/profile", str(exc))
        if not verify_password(payload.current_password, user.hashed_password):
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.password_incorrect", "Incorrect current password"),
            )
        updated = UserService.update_user(db, user.id, UserUpdate(password=payload.new_password))
        if not updated:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.password_changed", "Password changed"),
        )
    finally:
        db.close()


@router.post("/profile/2fa/setup", response_class=HTMLResponse)
def users_setup_two_factor(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if user.is_two_factor_enabled:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.twofa_already_enabled", "2FA is already enabled"),
            )
        secret = AuthService.generate_two_factor_secret()
        user.two_factor_secret = secret
        db.add(user)
        db.commit()
        db.refresh(user)
        provisioning_uri = AuthService.get_two_factor_provisioning_uri(user, secret)
        qr_code = _generate_qr_code_data_uri(provisioning_uri)
        allowlist_entries = UserIpAllowlistService.list_for_user(db, user.id)
        return templates.TemplateResponse(
            "users/profile.html",
            {
                "request": request,
                "user": user,
                "nav_user": user,
                "lang": lang,
                "t": t,
                "allowlist_entries": allowlist_entries,
                "message": _msg(lang, "web.msg.twofa_secret_generated", "2FA secret generated"),
                "two_factor_setup": {
                    "secret": secret,
                    "provisioning_uri": provisioning_uri,
                    "qr_code": qr_code,
                },
                "verification_required": not user.is_verified,
                "show_admin_link": _is_admin_link_visible(user),
            },
        )
    finally:
        db.close()


@router.post("/profile/2fa/enable")
def users_enable_two_factor(request: Request, lang: str, code: str = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if user.is_two_factor_enabled:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.twofa_already_enabled", "2FA is already enabled"),
            )
        if not user.two_factor_secret:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.twofa_setup_required", "2FA setup is required before enabling"),
            )
        if not AuthService.verify_two_factor_code(user, code):
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.invalid_otp", "Invalid 2FA code"),
            )
        user.is_two_factor_enabled = True
        db.add(user)
        db.commit()
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.twofa_enabled", "2FA enabled successfully"),
        )
    finally:
        db.close()


@router.post("/profile/2fa/disable")
def users_disable_two_factor(request: Request, lang: str, code: str = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        if not user.is_two_factor_enabled:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.twofa_not_enabled", "2FA is not enabled"),
            )
        if not AuthService.verify_two_factor_code(user, code):
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.invalid_otp", "Invalid 2FA code"),
            )
        user.is_two_factor_enabled = False
        user.two_factor_secret = None
        db.add(user)
        db.commit()
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.twofa_disabled", "2FA disabled successfully"),
        )
    finally:
        db.close()


@router.post("/profile/allowlist/add")
def users_allowlist_add(
    request: Request,
    lang: str,
    ip_or_network: str = Form(...),
    description: str | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        try:
            UserIpAllowlistService.create_entry(
                db,
                user_id=user.id,
                ip_or_network=ip_or_network,
                description=description,
                is_active=True,
            )
        except ValueError as exc:
            return _redirect_with_message(lang, "/users/profile", str(exc))
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.allowlist_added", "Allowed IP added"),
        )
    finally:
        db.close()


@router.post("/profile/allowlist/update")
def users_allowlist_update(
    request: Request,
    lang: str,
    entry_id: int = Form(...),
    ip_or_network: str | None = Form(default=None),
    description: str | None = Form(default=None),
    is_active: bool | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        try:
            entry = UserIpAllowlistService.update_entry(
                db,
                user_id=user.id,
                entry_id=entry_id,
                ip_or_network=ip_or_network or None,
                description=description or None,
                is_active=is_active,
            )
        except ValueError as exc:
            return _redirect_with_message(lang, "/users/profile", str(exc))
        if not entry:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.allowlist_entry_not_found", "Allowed IP entry not found"),
            )
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.allowlist_updated", "Allowed IP updated"),
        )
    finally:
        db.close()


@router.post("/profile/allowlist/delete")
def users_allowlist_delete(request: Request, lang: str, entry_id: int = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        user = _get_current_user_from_cookie(request, db, require_verified=False)
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        deleted = UserIpAllowlistService.delete_entry(db, user.id, entry_id)
        if not deleted:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.allowlist_entry_not_found", "Allowed IP entry not found"),
            )
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.allowlist_deleted", "Allowed IP deleted"),
        )
    finally:
        db.close()
