import requests
from rest_framework import mixins, viewsets, status
import logging
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    OpenApiParameter,
    OpenApiTypes,
    inline_serializer,
)
from django.db import transaction

from rest_framework.decorators import action, throttle_classes
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator

from authentication.models import ActivationCode, PasswordResetToken
from authentication.throttles import (
    AccountDeleteThrottle,
    ActivationThrottle,
    LoginThrottle,
    PasswordChangeThrottle,
    PasswordResetRequestThrottle,
    ProfilePhotoUploadThrottle,
    RegisterThrottle,
)
from authentication.utils import (
    generate_activation_code,
    send_account_activated_email,
    send_account_updated_email,
    send_confirmation_reset_password_email,
    send_password_change_email,
    send_reset_email,
)
from google.oauth2 import id_token

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from .serializers import (
    AccountDeleteSerializer,
    ActivationSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfilePictureSerializer,
    RegisterSerializer,
    MyTokenObtainPairSerializer,
    ProfileSerializer,
    ChangePasswordSerializer,
    UserSerializer,
)
from rest_framework import serializers

User = get_user_model()

logger = logging.getLogger("authentication")


def set_refresh_cookie(response, token: str):
    """Set the refresh token in an HttpOnly cookie."""
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=True if settings.DEBUG else False,
        samesite="Strict",
        max_age=60 * 60 * 24 * 7,
    )


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Refresh JWT access token",
    description="""
Refresh the JWT access token using the refresh token stored in an HttpOnly cookie.

**Security requirements:**
- Requires a valid CSRF token sent in the 'X-CSRFToken' header.
- If the CSRF token is missing or invalid, a 403 Forbidden response is returned.
- If the refresh token is missing from cookies, a 400 Bad Request is returned.
- If the refresh token is invalid or expired, a 401 Unauthorized is returned.

**Cookie required:**
- `refresh_token`: The JWT refresh token, stored in an HttpOnly cookie.

**Header required:**
- `X-CSRFToken`: The CSRF token. Must match the value sent by the server.

**Response:**
- 200 OK: New JWT access token and (optionally) a new refresh token cookie.
- 400 Bad Request: Missing refresh token in cookies.
- 401 Unauthorized: Invalid or expired refresh token.
- 403 Forbidden: Missing or invalid CSRF token.
- 500 Internal Server Error: Unhandled error (server-side).
""",
    responses={
        200: OpenApiResponse(description="Access token refreshed successfully."),
        400: OpenApiResponse(description="Refresh token missing from cookies."),
        401: OpenApiResponse(description="Refresh token invalid or expired."),
        403: OpenApiResponse(description="CSRF token missing or invalid."),
        500: OpenApiResponse(description="Internal server error."),
    },
    request=None,
    parameters=[
        OpenApiParameter(
            name="X-CSRFToken",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.HEADER,
            required=True,
            description="CSRF token sent in the header. Required for refreshing JWT.",
        )
    ],
)
@method_decorator(ensure_csrf_cookie, name="dispatch")
class CustomTokenRefreshView(TokenRefreshView):
    """
    Refresh JWT access token using HttpOnly cookie and CSRF protection.

    This endpoint extends the default TokenRefreshView and requires:
    - A valid refresh token stored in an HttpOnly cookie named 'refresh_token'.
    - A valid CSRF token passed in the 'X-CSRFToken' header.

    **Response codes:**
    - 200 OK: Access token refreshed and new refresh token cookie set.
    - 400 Bad Request: Refresh token missing from cookies.
    - 401 Unauthorized: Invalid or expired refresh token.
    - 403 Forbidden: Missing or invalid CSRF token.
    - 500 Internal Server Error: Unhandled server error.

    Usage example:
    ```
    POST /api/token/refresh/
    Cookie: refresh_token=<your-token>
    Header: X-CSRFToken: <your-csrf-token>
    ```
    Response:
    {
        "access": "<new-access-token>"
    }
    """

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token", None)

        if not refresh_token:
            logger.warning("[Token Refresh] Missing refresh token in cookies")
            return Response(
                {"detail": "Refresh token not found in cookies."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            logger.warning(f"[Token Refresh] {str(e)}")
            return Response({"detail": str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        data = serializer.validated_data
        access_token = data.get("access")
        new_refresh_token = data.get("refresh", refresh_token)

        response = Response({"access": access_token}, status=status.HTTP_200_OK)

        # Réinjecter le nouveau refresh token dans un cookie sécurisé
        set_refresh_cookie(response, new_refresh_token)

        logger.info("[Token Refresh] Access token refreshed and new refresh cookie set")
        return response


@extend_schema(
    tags=["Auth"],
    summary="Authenticate or register user via GitHub SSO",
    description="""Authentifie ou crée un utilisateur via SSO GitHub.
    Le frontend envoie le code d’autorisation GitHub (OAuth2) en POST.
    Le backend échange ce code contre un access_token, récupère l’email GitHub, crée ou connecte l’utilisateur, et retourne des tokens JWT.""",
    request=inline_serializer(
        name="GithubSSOLoginRequest",
        fields={"code": serializers.CharField(help_text="Code d'autorisation GitHub")},
    ),
    responses={
        200: OpenApiResponse(
            response=inline_serializer(
                name="GithubSSOLoginResponse",
                fields={
                    "refresh": serializers.CharField(help_text="JWT refresh token"),
                    "access": serializers.CharField(help_text="JWT access token"),
                },
            ),
            description="JWT tokens pour la session API",
        ),
        400: OpenApiResponse(
            response=inline_serializer(
                name="GithubSSOLoginErrorResponse",
                fields={"error": serializers.CharField()},
            ),
            description="Erreur ou code GitHub invalide",
        ),
    },
)
class GithubSSOLoginView(APIView):
    """
    Endpoint d'authentification SSO via GitHub.

    Reçoit en POST un "code" dans le corps de la requête (JSON).
    Échange le code contre un access_token GitHub, récupère l'utilisateur, crée/connecte le user Django et retourne les tokens JWT.

    - Corps attendu :
        {
            "code": "<code_github>"
        }

    - Réponse en cas de succès :
        {
            "refresh": "<jwt_refresh_token>",
            "access": "<jwt_access_token>"
        }

    - Réponse en cas d'erreur :
        {
            "error": "Invalid code"
        }
    """

    permission_classes = [AllowAny]

    def post(self, request):
        code = request.data.get("code")
        if not code:
            logger.warning("[GitHub SSO Login] No code provided")
            return Response(
                {"error": "No code provided"}, status=status.HTTP_400_BAD_REQUEST
            )

        token_resp = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            timeout=10,
        )
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            logger.warning("[GitHub SSO Login] Invalid code")
            return Response(
                {"error": "Invalid code"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 2. Récupère infos utilisateur chez GitHub
        user_resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"},
            timeout=10,
        )
        user_data = user_resp.json()
        email = user_data.get("email")
        # Si email non public, va le chercher explicitement
        if not email:
            logger.info(
                "[GitHub SSO Login] Email not found in user data, fetching emails"
            )
            email_resp = requests.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"},
                timeout=10,
            )
            email_list = email_resp.json()
            email = next((e["email"] for e in email_list if e.get("primary")), None)
            email = next((e["email"] for e in email_list if e.get("primary")), None)

        if not email:
            return Response(
                {"error": "Unable to retrieve email from GitHub"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 3. Crée ou récupère l'user local
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": user_data.get("name", ""),
                "is_active": True,
            },
        )
        if not user.is_active:
            user.is_active = True
            user.save()

        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        response = Response(
            {
                "message": "Login successful.",
                "access": access,
                "user": MyTokenObtainPairSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )

        set_refresh_cookie(response, str(refresh))
        logger.info(f"[GitHub SSO Login] Issued tokens for user {email}")
        return response


@extend_schema(
    tags=["Auth"],
    summary="Authenticate or register user via Google SSO",
    description="""
        Authenticates or creates a user using a Google OAuth2 token (SSO).
        Receives an ID token from the frontend (typically Angular), verifies it with Google,
        creates or updates the user, and returns JWT tokens for session management.
        The user account is automatically activated upon creation via SSO.

        Typical usage: the frontend obtains a Google ID token, sends it to this endpoint via POST,
        and receives refresh/access tokens for API authentication.
    """,
    request=inline_serializer(
        name="GoogleSSOLoginRequest",
        fields={
            "id_token": serializers.CharField(
                help_text="Google OAuth2 ID token obtained by the frontend"
            )
        },
    ),
    responses={
        200: OpenApiResponse(
            response=inline_serializer(
                name="GoogleSSOLoginResponse",
                fields={
                    "refresh": serializers.CharField(help_text="JWT refresh token"),
                    "access": serializers.CharField(help_text="JWT access token"),
                },
            ),
            description="JWT tokens returned for authenticated session",
        ),
        400: OpenApiResponse(
            response=inline_serializer(
                name="GoogleSSOLoginErrorResponse",
                fields={"error": serializers.CharField()},
            ),
            description="Invalid or missing token",
        ),
    },
)
class GoogleSSOLoginView(APIView):
    """
    API endpoint to authenticate or register a user via Google SSO (OAuth2).

    This endpoint expects a POST request containing an "id_token" field,
    which should be a Google OAuth2 ID token obtained from the frontend (e.g., Angular).

    The endpoint will:
    - Verify the ID token with Google.
    - Retrieve user info (email, first_name, last_name) from the token.
    - Create or update the user in the local database, setting is_active=True.
    - Return JWT access and refresh tokens for authentication.

    If the token is invalid or missing, returns HTTP 400 with an error message.

    Example request:
        POST /api/auth/google/
        {
            "id_token": "<google_id_token>"
        }

    Example success response:
        {
            "refresh": "<jwt_refresh_token>",
            "access": "<jwt_access_token>"
        }

    Example error response:
        {
            "error": "Invalid token"
        }
    """

    from google.auth.transport import requests

    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("id_token")
        if not token:
            logger.warning("[Google SSO Login] No token provided")
            return Response(
                {"error": "No token provided"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request())
            email = idinfo["email"]
            first_name = idinfo.get("given_name", "")
            last_name = idinfo.get("family_name", "")
            # Si tu veux récupérer plus d'infos, adapte ici

            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": first_name,
                    "last_name": last_name,
                    "is_active": True,  # <--- Active directement le compte SSO
                },
            )
            # Si le user existait déjà, assure-toi qu'il est bien actif
            if not user.is_active:
                user.is_active = True
                user.save()

            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            response = Response(
                {
                    "message": "Login successful.",
                    "access": access,
                    "user": MyTokenObtainPairSerializer(user).data,
                },
                status=status.HTTP_200_OK,
            )

            set_refresh_cookie(response, str(refresh))
            logger.info(
                f"[Google SSO Login] User {email} {'created' if created else 'logged in'} via SSO"
            )
            return response
        except ValueError:
            logger.warning("[Google SSO Login] Invalid token")
            return Response(
                {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Register a new user account via email",
    description="""
    Creates a new user account using the provided email and password, plus optional profile information.
    No username is required or stored; the email serves as the unique identifier.

    Upon successful registration:
    - The user account is created with `is_active=False`.
    - A 6-digit activation code is generated and stored.
    - The activation code is sent to the user's email.

    **Required fields in the request:**
    - `email`: User's email address (unique, used as login).
    - `password` and `password_confirm`: Passwords (must match, validated via Django security rules).
    - Optionally: `first_name`, `last_name`, `role`, `phone_number`, `address`, `city`, `country`, `profile_picture`, `date_of_birth`.

    **Responses:**
    - `201 Created`: Registration successful; activation code sent by email.
    - `400 Bad Request`: Validation errors (ex: email already used, passwords mismatch).
    - `500 Internal Server Error`: Unexpected server error.
    """,
    request=RegisterSerializer,
    responses={
        201: OpenApiResponse(description="User registered successfully."),
        400: OpenApiResponse(description="Validation error."),
        500: OpenApiResponse(description="Internal server error."),
    },
    auth=[],
)
@method_decorator(ensure_csrf_cookie, name="dispatch")
@throttle_classes([RegisterThrottle])
class RegisterView(APIView):
    """
    API endpoint to register a new user account using an email address.

    - The user account is created with `is_active=False`.
    - A 6-digit activation code is generated and stored for future account activation.
    - The activation code is sent to the provided email address.

    **Request payload must include:**
    - `email` (string, required): Used as the unique user identifier.
    - `password` and `password_confirm` (string, required): Passwords must match and comply with security rules.
    - Optional profile fields: `first_name`, `last_name`, `role`, `phone_number`, `address`, `city`, `country`, `profile_picture`, `date_of_birth`.

    **Responses:**
    - 201 Created: User registered successfully. Activation code sent by email.
    - 400 Bad Request: Validation error (ex: email already used, passwords mismatch, invalid field).
    - 500 Internal Server Error: Unexpected server error.

    The username field is NOT used; registration and authentication are performed via email only.
    """

    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save(is_active=False)

        code = generate_activation_code(length=6)
        ActivationCode.objects.create(user=user, code=code)

        send_reset_email(user, code)

        return user

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    user = self.perform_create(serializer)
                logger.info(f"[Register] New user registered: {user.email}")
                return Response(
                    {
                        "message": "User registered successfully. Please check your email for the activation code."
                    },
                    status=status.HTTP_201_CREATED,
                )
            except Exception as e:
                logger.error(f"RegisterView error: {e}")
                return Response(
                    {"error": "Internal server error."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            errors = serializer.errors
            if "email" in errors and any(
                "already exists" in msg for msg in errors["email"]
            ):
                errors["email"] = [
                    "Unable to create account. Contact support if the problem persists."
                ]
            logger.warning(f"[Register] Registration failed: {errors}")
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ensure_csrf_cookie, name="dispatch")
@throttle_classes([ActivationThrottle])
class ActivateAccountView(APIView):
    """
    Activate a user account using a 6-digit activation code.

    Checks the provided code for validity and expiration. Once validated:
    - The user is marked as active.
    - The code is marked as used.

    Request:
        - `code`: The 6-digit activation code.

    Response:
        - 200 OK: If the account is successfully activated.
        - 400 Bad Request: If the code is invalid or expired.
        - 500 Internal Server Error: If there is an issue processing the request.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        request=ActivationSerializer,
        responses={
            200: OpenApiResponse(description="Account activated successfully."),
            400: OpenApiResponse(description="Invalid or expired activation code."),
        },
        summary="Activate a user account",
        description="Activate a user account using an activation code received via email or SMS.",
        auth=[],
    )
    def post(self, request):
        serializer = ActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        try:
            activation = ActivationCode.objects.get(code=code, is_used=False)
            user = activation.user
        except ActivationCode.DoesNotExist:
            logger.warning(f"[Activate Account] Invalid activation code: {code}")
            return Response(
                {"detail": "Invalid activation code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if activation.is_expired():
            logger.warning(f"[Activate Account] Activation code expired: {code}")
            return Response(
                {"detail": "The code has expired."}, status=status.HTTP_400_BAD_REQUEST
            )

        user.is_active = True
        user.save()

        activation.is_used = True
        activation.save()

        send_account_activated_email(user, settings.FRONTEND_URL + "/login")
        logger.info(f"[Activate Account] User {user.email} activated their account.")

        return Response(
            {"detail": "Account activated successfully."}, status=status.HTTP_200_OK
        )


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Login and obtain access/refresh tokens",
    description="Authenticate user and return JWT access token and set refresh token in cookie.",
    request=MyTokenObtainPairSerializer,
    responses={
        200: OpenApiResponse(
            description="Login successful. Access token returned.",
            examples=[
                OpenApiExample(
                    "Login Success",
                    value={
                        "message": "Login successful.",
                        "access_token": "<JWT access token>",
                        "user": {
                            "id": 1,
                            "email": "user@example.com",
                            "username": "username",
                        },
                    },
                    status_codes=["200"],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Bad request: Invalid data format.",
            examples=[
                OpenApiExample(
                    "Invalid Format",
                    value={"error": "Invalid data. Email and password are required."},
                    status_codes=["400"],
                )
            ],
        ),
        401: OpenApiResponse(
            description="Unauthorized. Invalid credentials.",
            examples=[
                OpenApiExample(
                    "Invalid Credentials",
                    value={"error": "Invalid credentials."},
                    status_codes=["401"],
                )
            ],
        ),
    },
    auth=[],
)
@method_decorator(ensure_csrf_cookie, name="dispatch")
@throttle_classes([LoginThrottle])
class LoginView(APIView):
    """
    Authenticate a user and obtain JWT tokens.

    Validates user credentials and returns:
    - An access token in the response body.
    - A refresh token stored as an HttpOnly cookie.

    Request:
        - Email and password.

    Response:
        - 200 OK: If authentication is successful.
        - 400 Bad Request: If input data is invalid.
        - 401 Unauthorized: If credentials are incorrect.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = MyTokenObtainPairSerializer(data=request.data)

        if not serializer.is_valid():
            logger.warning(
                f"[Login Attempt] email={request.data.get('email')} result=FAILED ip={get_client_ip(request)} user-agent={request.META.get('HTTP_USER_AGENT')}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.user

        if not user.is_active:
            logger.warning(
                f"[Login Attempt] email={user.email} result=FAILED (inactive) ip={get_client_ip(request)}"
            )
            return Response(
                {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
            )

        try:
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            user.update_last_login()

            response = Response(
                {
                    "message": "Login successful.",
                    "access_token": access,
                    "user": serializer.validated_data["user"],
                },
                status=status.HTTP_200_OK,
            )

            set_refresh_cookie(response, str(refresh))

            logger.info(
                f"[Login Success] email={user.email} ip={get_client_ip(request)}"
            )
            return response

        except Exception as e:
            logger.error(
                f"[Login Error] email={user.email} ip={get_client_ip(request)} error={e}"
            )
            return Response(
                {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
            )


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Logout user and blacklist refresh token",
    description="""
Logout the current user by blacklisting the JWT refresh token and clearing it from cookies.

**Security requirements:**
- The user must be authenticated.
- A valid refresh token must be provided in the cookies.

**Process:**
- The view reads the 'refresh_token' cookie.
- If present, the token is blacklisted (cannot be reused).
- The cookie is deleted from the client.
- Returns a success response if everything is valid.

**Response codes:**
- 205 Reset Content: Logout successful; token blacklisted, cookie deleted.
- 400 Bad Request: No or invalid refresh token provided.
- 500 Internal Server Error: Unexpected server-side error.
""",
    responses={
        205: OpenApiResponse(description="Logout successful. Token blacklisted."),
        400: OpenApiResponse(description="No or invalid refresh token provided."),
        500: OpenApiResponse(description="Internal server error."),
    },
)
@method_decorator(ensure_csrf_cookie, name="dispatch")
class LogoutView(APIView):
    """
    API endpoint to logout a user and blacklist the JWT refresh token.

    - Reads the 'refresh_token' from cookies.
    - Blacklists the refresh token to prevent reuse.
    - Deletes the 'refresh_token' cookie from the client.

    Requirements:
        - User must be authenticated.
        - A valid refresh token must be present in cookies.

    Responses:
        - 205 Reset Content: Logout successful; token blacklisted.
        - 400 Bad Request: No or invalid refresh token provided.
        - 500 Internal Server Error: Unexpected server error.

    Usage example:
    ```
    POST /api/logout/
    Cookie: refresh_token=<your-token>
    Header: Authorization: Bearer <access-token>
    ```
    Response:
    {
        "message": "Logout successful."
    }
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                logger.warning(
                    f"[Logout] No refresh token found in cookies for user {request.user.email}."
                )
                return Response(
                    {"error": "No refresh token found."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            response = Response(
                {"message": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT
            )
            response.delete_cookie("refresh_token")
            logger.info(
                f"[Logout] User {request.user.email} successfully logged out and token blacklisted."
            )
            return response
        except TokenError:
            return Response(
                {"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"LogoutView error: {e}")
            return Response(
                {"error": "Internal server error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@method_decorator(ensure_csrf_cookie, name="dispatch")
@throttle_classes([PasswordResetRequestThrottle])
class PasswordResetRequestView(APIView):
    """
    PasswordResetRequestView

    Allow users to request a password reset link by submitting their email address.

    This endpoint accepts an email address and, if a user with that email exists,
    sends a reset link containing a token to that address. If the email is not registered,
    a generic success response is still returned for security reasons.

    Methods:
        POST: Submit an email address to trigger password reset instructions.

    Permissions:
        - No authentication required.

    Request Body:
        {
            "email": "user@example.com"
        }

    Responses:
        200 OK:
            {
                "detail": "If that email is registered, a reset link will be sent."
            }

        400 Bad Request:
            {
                "email": ["This field is required."]
            }

        500 Internal Server Error:
            {
                "detail": "Internal server error."
            }
    """

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        methods=["POST"],
        summary="Request password reset",
        description=(
            "Submit an email to receive a password reset link if the email is registered.\n\n"
            "For security reasons, the response is the same whether the email exists or not."
        ),
        request=PasswordResetRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset link sent if email exists."
            ),
            400: OpenApiResponse(description="Validation error."),
            500: OpenApiResponse(description="Internal server error."),
        },
        examples=[
            OpenApiExample(
                "Request example",
                value={"email": "user@example.com"},
                request_only=True,
            ),
            OpenApiExample(
                "Success response example",
                value={
                    "detail": "If that email is registered, a reset link will be sent."
                },
                response_only=True,
            ),
        ],
        auth=[],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            user_qs = User.objects.filter(email=email)
            if user_qs.exists() and user_qs.get().is_active:
                user = user_qs.first()
                try:
                    reset_token = PasswordResetToken.objects.create(user=user)
                    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token.token}"
                    send_reset_email(user, reset_link)
                    logger.info(
                        f"[PasswordResetRequest] Reset link sent to {user.email}"
                    )
                except Exception as e:
                    logger.error(
                        f"[PasswordResetRequest] Error sending email to {email}: {e}"
                    )
                    # Do not expose internal errors to user for security
            else:
                logger.info(
                    f"[PasswordResetRequest] Password reset requested for inactive email: {email}"
                )

            return Response(
                {"detail": "If that email is registered, a reset link will be sent."},
                status=status.HTTP_200_OK,
            )
        else:
            logger.warning(
                f"[PasswordResetRequest] Validation errors: {serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ensure_csrf_cookie, name="dispatch")
class PasswordResetConfirmView(APIView):
    """
    PasswordResetConfirmView

    Confirm and finalize the password reset using the provided reset token.

    This endpoint allows a user to reset their password by submitting a valid, non-expired token
    along with the new password and its confirmation. The new password must meet the defined
    security policy (minimum length, complexity, etc.).

    Methods:
        POST: Submit reset token and new password.

    Permissions:
        - No authentication required.

    Request Body:
        {
            "token": "a3f1e71a-7f38-4a9c-bd47-79d3f1d85412",
            "new_password": "newStrongPassword123!",
            "new_password_confirm": "newStrongPassword123!"
        }

    Responses:
        200 OK:
            {
                "detail": "Password has been reset successfully."
            }

        400 Bad Request:
            {
                "detail": "Reset token has expired." | "Passwords do not match."
            }

        404 Not Found:
            {
                "detail": "Not found."
            }

        500 Internal Server Error:
            {
                "error": "Internal server error."
            }
    """

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        methods=["POST"],
        summary="Confirm password reset",
        description=(
            "Submit a valid reset token along with new password and its confirmation.\n\n"
            "If token is valid and not expired, password will be updated."
        ),
        request=PasswordResetConfirmSerializer,
        responses={
            200: OpenApiResponse(description="Password reset successfully."),
            400: OpenApiResponse(
                description="Invalid token, expired token, inactive user or validation errors."
            ),
            404: OpenApiResponse(description="Reset token not found."),
            500: OpenApiResponse(description="Internal server error."),
        },
        examples=[
            OpenApiExample(
                "Request example",
                value={
                    "token": "a3f1e71a-7f38-4a9c-bd47-79d3f1d85412",
                    "new_password": "newStrongPassword123!",
                    "new_password_confirm": "newStrongPassword123!",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Success response example",
                value={"detail": "Password has been reset successfully."},
                response_only=True,
            ),
        ],
        auth=[],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data["token"]
            new_password = serializer.validated_data["new_password"]
            try:
                reset_token = get_object_or_404(
                    PasswordResetToken, token=token, is_used=False
                )

                if reset_token.is_expired():
                    logger.warning(f"[PasswordResetConfirm] Expired token: {token}")
                    return Response(
                        {"detail": "Reset token has expired."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                if reset_token.user.is_active is False:
                    logger.warning(
                        f"[PasswordResetConfirm] Inactive user for token: {token}"
                    )
                    return Response(
                        {"detail": "User account is inactive."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                user = reset_token.user
                user.set_password(new_password)
                user.save()

                reset_token.is_used = True
                reset_token.save()

                logger.info(
                    f"[PasswordResetConfirm] Password reset successfully for user {user.email}"
                )

                send_confirmation_reset_password_email(
                    user, settings.FRONTEND_URL + "/login"
                )
                return Response(
                    {"detail": "Password has been reset successfully."},
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                logger.warning(f"token not found or error: {e}")
                return Response(
                    {"detail": "Reset token not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            logger.warning(
                f"[PasswordResetConfirm] Validation errors: {serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Admin"],
    summary="Admin: Manage user accounts",
    description=(
        "Admin-only endpoint to list, retrieve, update, or delete user accounts.\n\n"
        "**Available operations:**\n"
        "- `GET /admin/users/`: List all users\n"
        "- `GET /admin/users/{id}/`: Retrieve a specific user\n"
        "- `POST /admin/users/`: Create a new user account\n"
        "- `PUT /admin/users/{id}/`: Update a user account\n"
        "- `DELETE /admin/users/{id}/`: Delete a user account\n\n"
        "**Possible responses:**\n"
        "- `200 OK`: Request successful\n"
        "- `201 Created`: User created successfully\n"
        "- `204 No Content`: User successfully deleted\n"
        "- `400 Bad Request`: Validation error\n"
        "- `403 Forbidden`: Access restricted to admins\n"
        "- `404 Not Found`: User not found"
    ),
    responses={
        200: UserSerializer,
        204: OpenApiResponse(description="User deleted successfully."),
        403: OpenApiResponse(description="Access denied."),
        404: OpenApiResponse(description="User not found."),
    },
)
@method_decorator(ensure_csrf_cookie, name="dispatch")
class AdminUserView(ModelViewSet):
    """
    ViewSet for administrative user management.

    Allows staff users with admin privileges to:
    - List all users
    - Create new user accounts
    - Retrieve user details by ID
    - Update user accounts
    - Delete user accounts

    Permissions:
        - Access restricted to users with admin rights (IsAdminUser).
    """

    queryset = User.objects.all()
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    logger.warning("[AdminUserView] Admin user management endpoint initialized.")

    # Pagination, Filtrage et Recherche
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["email", "is_active", "role", "last_name", "first_name"]
    search_fields = ["email", "first_name", "last_name"]
    ordering_fields = ["date_joined", "last_name", "role"]
    ordering = ["last_name"]

    def perform_create(self, serializer):
        user = serializer.save(is_active=True)

        return user

    def create(self, request, *args, **kwargs):
        try:
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = self.perform_create(serializer)
                logger.info(f"[AdminUserView] New user registered: {user.email}")
                return Response(
                    {"message": "User registered successfully."},
                    status=status.HTTP_201_CREATED,
                )
            logger.warning(f"[AdminUserView] Registration failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"[AdminUserView] Registration error: {e}")
            return Response(
                {"error": "Internal server error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        logger.info(f"[AdminUserView] Updating user: {kwargs.get('pk', 'Unknown')}")
        return super().update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        logger.info(
            f"[AdminUserView] Deleting user: {request.data.get('email', 'Unknown')}"
        )
        return super().delete(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        logger.info("[AdminUserView] Listing users")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"[AdminUserView] Retrieving user: {kwargs.get('pk', 'Unknown')}")
        return super().retrieve(request, *args, **kwargs)


@extend_schema(tags=["User Profile"])
@method_decorator(ensure_csrf_cookie, name="dispatch")
class UserProfileViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    @extend_schema(
        summary="Lire le profil de l'utilisateur connecté",
        description="Retourne toutes les informations du profil de l'utilisateur authentifié.",
        responses={
            200: ProfileSerializer,
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    def retrieve(self, request, *args, **kwargs):
        logger.info(
            f"[UserProfileViewSet] Retrieving profile for user: {request.user.email}"
        )
        serializer = self.get_serializer(self.get_object())
        return Response(serializer.data)

    @extend_schema(
        summary="Modifier le profil",
        description="Permet de modifier partiellement les informations du profil utilisateur. Un email de notification est envoyé après modification.",
        request=ProfileSerializer,
        responses={
            200: OpenApiResponse(description="Profil mis à jour"),
            400: OpenApiResponse(description="Validation error"),
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        try:
            send_account_updated_email(user)
        except Exception as e:
            logger.error(
                f"[UserProfileViewSet] Error sending account update email for user: {request.user.email}, Error: {repr(e)}"
            )
            return Response(
                {"message": "Profile updated successfully, but failed to send email."},
                status=200,
            )
        logger.info(
            f"[UserProfileViewSet] Updated profile for user: {request.user.email}"
        )
        return Response({"message": "Profile updated successfully."})

    @extend_schema(
        summary="Supprimer le compte utilisateur",
        description="Supprime le compte de l'utilisateur après confirmation via passphrase.",
        request=AccountDeleteSerializer,
        responses={
            200: OpenApiResponse(description="Compte supprimé"),
            400: OpenApiResponse(description="Erreur de validation"),
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    @throttle_classes([AccountDeleteThrottle])
    def destroy(self, request, *args, **kwargs):
        serializer = AccountDeleteSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        self.get_object().delete()
        logger.info(
            f"[UserProfileViewSet] Deleted account for user: {request.user.email}"
        )
        return Response({"message": "Account deleted successfully."})

    @extend_schema(
        summary="Changer le mot de passe",
        description="Permet à l'utilisateur authentifié de changer son mot de passe. Un email de notification est envoyé après changement.",
        request=ChangePasswordSerializer,
        responses={
            200: OpenApiResponse(description="Mot de passe changé"),
            400: OpenApiResponse(description="Erreur de validation"),
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    @action(detail=False, methods=["post"], url_path="change-password")
    @throttle_classes([PasswordChangeThrottle])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        try:
            send_password_change_email(self.get_object())
        except Exception as e:
            logger.error(
                f"[UserProfileViewSet] Error sending password change email for user: {request.user.email}, Error: {repr(e)}"
            )
            return Response(
                {"message": "Password changed successfully, but failed to send email."},
                status=200,
            )
        logger.info(
            f"[UserProfileViewSet] Password changed for user: {request.user.email}"
        )
        return Response({"message": "Password changed successfully."})

    @extend_schema(
        summary="Uploader la photo de profil",
        description="Permet d'uploader une nouvelle photo de profil. Le champ 'profile_picture' est obligatoire.",
        request=ProfilePictureSerializer,
        responses={
            200: OpenApiResponse(description="Photo de profil uploadée"),
            400: OpenApiResponse(description="Erreur de validation"),
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    @action(detail=False, methods=["post"], url_path="upload-photo")
    @throttle_classes([ProfilePhotoUploadThrottle])
    def upload_photo(self, request):
        serializer = ProfilePictureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.get_object()
        if user.profile_picture:
            user.profile_picture.delete(save=False)
        user.profile_picture = serializer.validated_data["profile_picture"]
        user.save()
        logger.info(
            f"[UserProfileViewSet] Profile picture uploaded for user: {request.user.email}"
        )
        return Response({"message": "Profile picture uploaded successfully."})

    @extend_schema(
        summary="Supprimer la photo de profil",
        description="Supprime la photo de profil de l'utilisateur connecté.",
        responses={
            200: OpenApiResponse(description="Photo supprimée"),
            400: OpenApiResponse(description="Aucune photo à supprimer"),
            401: OpenApiResponse(description="Authentification requise"),
        },
    )
    @action(detail=False, methods=["delete"], url_path="delete-photo")
    @throttle_classes([ProfilePhotoUploadThrottle])
    def delete_photo(self, request):
        user = self.get_object()
        if user.profile_picture:
            user.profile_picture.delete(save=False)
            user.profile_picture = None
            user.save()
            logger.info(
                f"[UserProfileViewSet] Profile picture deleted for user: {request.user.email}"
            )
            return Response({"message": "Profile picture deleted successfully."})
        logger.warning(
            f"[UserProfileViewSet] No profile picture to delete for user: {request.user.email}"
        )
        return Response({"message": "No profile picture to delete."}, status=400)
