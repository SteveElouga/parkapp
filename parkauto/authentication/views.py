import logging
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, OpenApiParameter, OpenApiTypes
from django.db import transaction

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie

from authentication.models import ActivationCode, PasswordResetToken
from authentication.utils import generate_activation_code, send_account_activated_email, send_account_updated_email, send_confirmation_reset_password_email, send_password_change_email, send_reset_email

from .serializers import (
    AccountDeleteSerializer, ActivationSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, ProfilePictureSerializer, RegisterSerializer, MyTokenObtainPairSerializer,
    ProfileSerializer, ChangePasswordSerializer, UserSerializer
)

User = get_user_model()

logger = logging.getLogger('authentication')


def set_refresh_cookie(response, token: str):
    """Set the refresh token in an HttpOnly cookie."""
    response.set_cookie(
        key='refresh_token',
        value=token,
        httponly=True,
        samesite='Strict',
        max_age=60 * 60 * 24 * 7,
    )


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Refresh JWT access token",
    description=(
        "Refresh the JWT access token using the refresh token stored in an HttpOnly cookie.\n"
        "Requires a valid CSRF token to be sent in the 'X-CSRFToken' header.\n"
        "If the CSRF token is missing or invalid, a 403 Forbidden response is returned."
    ),
    responses={
        200: OpenApiResponse(description="Access token refreshed successfully."),
        403: OpenApiResponse(description="CSRF token missing or invalid."),
        401: OpenApiResponse(description="Refresh token invalid or expired."),
    },
    request=None,
    parameters=[
        OpenApiParameter(
            name="X-CSRFToken",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.HEADER,
            required=True,
            description="CSRF token sent in the header. Required for refreshing JWT."
        )
    ]
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class CustomTokenRefreshView(TokenRefreshView):
    """
    Refresh JWT access token using HttpOnly cookie and CSRF protection.

    This view extends the default TokenRefreshView and requires:
    - A valid refresh token stored in an HttpOnly cookie.
    - A valid CSRF token passed in the `X-CSRFToken` header.

    Returns:
        200 OK: If the access token is successfully refreshed.
        401 Unauthorized: If the refresh token is invalid or expired.
        403 Forbidden: If the CSRF token is missing or invalid.
        500 Internal Server Error: If there is an issue processing the request.
    """

    def post(self, request, *args, **kwargs):

        refresh_token = request.COOKIES.get('refresh_token', None)

        if not refresh_token:
            logger.warning("[Token Refresh] Missing refresh token in cookies")
            return Response({"detail": "Refresh token not found in cookies."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            logger.warning(f"[Token Refresh] {str(e)}")
            return Response(
                {"detail": str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )

        data = serializer.validated_data
        access_token = data.get("access")
        new_refresh_token = data.get("refresh", refresh_token)

        response = Response(
            {"access": access_token},
            status=status.HTTP_200_OK
        )

        # Réinjecter le nouveau refresh token dans un cookie sécurisé
        set_refresh_cookie(response, new_refresh_token)

        logger.info(
            "[Token Refresh] Access token refreshed and new refresh cookie set")

        return response


# @extend_schema(
#     tags=["Auth"],
#     methods=["GET"],
#     summary="Get CSRF token",
#     description=(
#         "Retrieve a CSRF token to be used in subsequent unsafe HTTP requests (POST, PUT, DELETE).\n"
#         "This endpoint returns the CSRF token in the response body as well as in a cookie accessible to JavaScript.\n"
#         "Call this endpoint before making requests that require CSRF protection."
#     ),
#     responses={
#         200: OpenApiResponse(description="CSRF token set successfully and returned in response."),
#     },
#     auth=[]
# )
# class GetCSRFToken(APIView):
#     """
#     Retrieve a CSRF token for client-side usage.

#     This endpoint returns a CSRF token:
#     - In the response body (`csrfToken` key).
#     - As a cookie accessible to JavaScript (non-HttpOnly).

#     Call this endpoint before making unsafe HTTP requests (e.g., POST, PUT, DELETE).
#     Returns:
#         200 OK: CSRF token successfully generated and returned.
#         500 Internal Server Error: If there is an issue generating the CSRF token.
#     """

#     permission_classes = [permissions.AllowAny]

#     def get(self, request, *args, **kwargs):
#         csrf_token = get_token(request)
#         response = Response({'csrfToken': csrf_token},
#                             status=status.HTTP_200_OK)

#         response.set_cookie(
#             key='csrftoken',
#             value=csrf_token,
#             max_age=3600,
#             httponly=False,
#             samesite='Lax',  # ou 'Strict' selon besoin
#             secure=False,    # True en prod HTTPS, False en dev HTTP
#         )
#         logger.info("[CSRF] CSRF token generated and returned.")
#         return response


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Register new user",
    description="Register a new user by providing all required credentials.",
    request=RegisterSerializer,
    responses={
        201: OpenApiResponse(description="User registered successfully."),
        400: OpenApiResponse(description="Validation error."),
        500: OpenApiResponse(description="Internal server error.")
    },
    auth=[]
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class RegisterView(APIView):
    """
    Register a new user account.

    Creates a user account with `is_active=False` and generates a 6-digit activation code.
    The activation code is stored and can later be used to activate the account.

    Request:
        - Email, password, and other required registration fields.

    Response:
        - 201 Created: If registration is successful.
        - 400 Bad Request: If validation fails.
        - 500 Internal Server Error: If something goes wrong during processing.
        - Sends an activation code to the user's email.
    """

    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save(is_active=False)

        code = generate_activation_code(length=6)
        ActivationCode.objects.create(user=user, code=code)

        send_reset_email(user, code)

        return user

    def post(self, request):
        try:
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                with transaction.atomic():
                    user = self.perform_create(serializer)
                logger.info(f"[Register] New user registered: {user.email}")
                return Response(
                    {"message": "User registered successfully. Please check your email for the activation code."},
                    status=status.HTTP_201_CREATED
                )
            logger.warning(
                f"[Register] Registration failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"RegisterView error: {e}")
            return Response({"error": "Internal server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(ensure_csrf_cookie, name='dispatch')
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
        auth=[]
    )
    def post(self, request):
        serializer = ActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        try:
            activation = ActivationCode.objects.get(code=code, is_used=False)
            user = activation.user
        except ActivationCode.DoesNotExist:
            logger.warning(
                f"[Activate Account] Invalid activation code: {code}")
            return Response({"detail": "Invalid activation code."}, status=status.HTTP_400_BAD_REQUEST)

        if activation.is_expired():
            logger.warning(
                f"[Activate Account] Activation code expired: {code}")
            return Response({"detail": "The code has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.save()

        activation.is_used = True
        activation.save()

        send_account_activated_email(user, settings.FRONTEND_URL + "/login")
        logger.info(
            f"[Activate Account] User {user.email} activated their account.")

        return Response({"detail": "Account activated successfully."}, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Login and obtain access/refresh tokens",
    description="Authenticate user and return JWT access token and set refresh token in cookie.",
    request=MyTokenObtainPairSerializer,
    responses={
        200: OpenApiResponse(description="Login successful. Access token returned."),
        401: OpenApiResponse(description="Invalid credentials."),
        400: OpenApiResponse(description="Validation error."),
    },
    auth=[]
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
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
            logger.warning(f"[Login] Invalid input: {serializer.errors}")
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.user

        if not user.is_active:
            logger.warning(f"[Login] Inactive account: {user.email}")
            return Response({"error": "Account is inactive."}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        user.update_last_login()

        response = Response({
            "message": "Login successful.",
            "access_token": access,
            "user": serializer.validated_data["user"],
        }, status=status.HTTP_200_OK)

        set_refresh_cookie(response, str(refresh))

        logger.info(f"[Login] User {user.email} logged in.")
        return response


@extend_schema(
    tags=["Auth"],
    methods=["POST"],
    summary="Logout user and blacklist refresh token",
    description="Logout current user by blacklisting refresh token and clearing it from cookies.",
    responses={
        205: OpenApiResponse(description="Logout successful. Token blacklisted."),
        400: OpenApiResponse(description="No or invalid refresh token provided."),
        500: OpenApiResponse(description="Internal server error.")
    }
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class LogoutView(APIView):
    """
    Logout a user and blacklist the refresh token.

    Deletes the `refresh_token` cookie and blacklists the token to prevent reuse.

    Requirements:
        - User must be authenticated.
        - A valid refresh token must be present in cookies.

    Response:
        - 205 Reset Content: Logout successful.
        - 400 Bad Request: No or invalid refresh token provided.
        - 500 Internal Server Error: On unexpected error.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if not refresh_token:
                logger.warning(
                    f"[Logout] No refresh token found in cookies for user {request.user.email}.")
                return Response({"error": "No refresh token found."}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()

            response = Response({"message": "Logout successful."},
                                status=status.HTTP_205_RESET_CONTENT)
            response.delete_cookie('refresh_token')
            logger.info(
                f"[Logout] User {request.user.email} successfully logged out and token blacklisted.")
            return response
        except TokenError:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"LogoutView error: {e}")
            return Response({"error": "Internal server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=["Auth"],
    methods=["PUT"],
    summary="Retrieve or update user profile",
    description="Allows authenticated users to retrieve or update their profile information.",
    request=ProfileSerializer,
    responses={
        200: ProfileSerializer,
        400: OpenApiResponse(description="Validation error."),
        401: OpenApiResponse(description="Authentication required."),
        500: OpenApiResponse(description="Internal server error.")
    }
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = ProfileSerializer(
            request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(
                f"[Profile Update] User {request.user.email} updated their profile.")
            send_account_updated_email(request.user)
            return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)
        logger.warning(
            f"[Profile Update] Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Auth"],
    summary="Change the password of the authenticated user",
    description=(
        "Allows an authenticated user to change their password by providing their current password, "
        "a new password, and a confirmation of the new password.\n\n"
        "The new password must comply with the following security rules:\n"
        "- Minimum of 8 characters\n"
        "- At least one uppercase letter\n"
        "- At least one lowercase letter\n"
        "- At least one digit\n"
        "- At least one special character\n\n"
        "**Possible responses:**\n"
        "- `200 OK`: Password changed successfully\n"
        "- `400 Bad Request`: Validation error (e.g., password mismatch, wrong current password...)\n"
        "- `403 Forbidden`: Unauthorized (missing or invalid token)\n"
        "- `500 Internal Server Error`: Unexpected server error"
    ),
    request=ChangePasswordSerializer,
    responses={
        200: OpenApiResponse(description="Password changed successfully."),
        400: OpenApiResponse(description="Validation error."),
        403: OpenApiResponse(description="Unauthorized."),
        500: OpenApiResponse(description="Internal server error."),
    },
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class ChangePasswordView(APIView):
    """
    ChangePasswordView

    Handle password change for the currently authenticated user.

    This endpoint allows an authenticated user to change their password
    by providing the current password, a new password, and its confirmation.
    The new password must meet the following security criteria:

    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Must not contain whitespace

    Methods:
        POST: Validate and update the user's password.

    Permissions:
        - User must be authenticated.

    Request body:
        {
            "old_password": "CurrentPassword123!",
            "new_password": "NewPassword!1",
            "new_password_confirm": "NewPassword!1"
        }

    Responses:
        200 OK:
            {
                "detail": "Password successfully changed."
            }

        400 Bad Request:
            {
                "non_field_errors": [...],  # Validation issues (e.g., mismatch, weak password)
                "old_password": [...],      # Incorrect current password
                "new_password": [...],      # Invalid format
            }

        403 Forbidden:
            {
                "detail": "Authentication credentials were not provided."
            }
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            logger.info(
                f"[ChangePassword] Password changed for user: {request.user.email}")
            send_password_change_email(request.user)
            return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)

        logger.warning(
            f"[ChangePassword] Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Auth"],
    methods=["GET"],
    summary="Retrieve authenticated user profile",
    description=(
        "Returns the profile information of the currently authenticated user.\n\n"
        "**Possible responses:**\n"
        "- `200 OK`: Successfully returns user data\n"
        "- `403 Forbidden`: User not authenticated"
    ),
    responses={
        200: UserSerializer,
        403: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
        500: OpenApiResponse(description="Internal server error.")
    },
)
class CurrentUserView(APIView):
    """
    Get the authenticated user's basic profile data.

    Returns minimal user info (usually name, email, ID, etc.)

    Response:
        - 200 OK: If the user is authenticated.
        - 403 Forbidden: If not authenticated.
        - 500 Internal Server Error: On unexpected error.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            serializer = UserSerializer(request.user)
            logger.info(
                f"[CurrentUser] Profile requested by user: {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"CurrentUserView error: {e}")
            return Response({"error": "Internal server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(ensure_csrf_cookie, name='dispatch')
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
            200: OpenApiResponse(description="Password reset link sent if email exists."),
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
                    "detail": "If that email is registered, a reset link will be sent."},
                response_only=True,
            ),
        ],
        auth=[]
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user_qs = User.objects.filter(email=email)
            if user_qs.exists():
                user = user_qs.first()
                try:
                    reset_token = PasswordResetToken.objects.create(user=user)
                    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token.token}"
                    send_reset_email(user, reset_link)
                    logger.info(
                        f"[PasswordResetRequest] Reset link sent to {user.email}")
                except Exception as e:
                    logger.error(
                        f"[PasswordResetRequest] Error sending email to {email}: {e}")
                    # Do not expose internal errors to user for security
            else:
                logger.info(
                    f"[PasswordResetRequest] Password reset requested for non-existent email: {email}")

            return Response(
                {"detail": "If that email is registered, a reset link will be sent."},
                status=status.HTTP_200_OK
            )
        else:
            logger.warning(
                f"[PasswordResetRequest] Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ensure_csrf_cookie, name='dispatch')
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
            400: OpenApiResponse(description="Invalid token, expired token, or validation errors."),
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
        auth=[]
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            try:
                reset_token = get_object_or_404(
                    PasswordResetToken, token=token, is_used=False)

                if reset_token.is_expired():
                    logger.warning(
                        f"[PasswordResetConfirm] Expired token: {token}")
                    return Response(
                        {"detail": "Reset token has expired."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                user = reset_token.user
                user.set_password(new_password)
                user.save()

                reset_token.is_used = True
                reset_token.save()

                logger.info(
                    f"[PasswordResetConfirm] Password reset successfully for user {user.email}")

                send_confirmation_reset_password_email(
                    user, settings.FRONTEND_URL + "/login")
                return Response(
                    {"detail": "Password has been reset successfully."},
                    status=status.HTTP_200_OK
                )
            except Exception as e:
                logger.warning(f"token not found or error: {e}")
                return Response(
                    {"detail": "Reset token not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            logger.warning(
                f"[PasswordResetConfirm] Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ensure_csrf_cookie, name='dispatch')
class DeleteOwnAccountView(APIView):
    """
    API endpoint that allows an authenticated user to permanently delete their own account.

    The deletion is **irreversible** and requires confirmation via a `passphrase` 
    (typically the user's current password) to prevent accidental or unauthorized deletions.

    Permissions:
        - Must be authenticated (IsAuthenticated)

    Request body:
        {
            "passphrase": "your_current_password"
        }

    Responses:
        - 204 No Content: Account successfully deleted.
        - 400 Bad Request: Invalid or missing passphrase.
        - 401 Unauthorized: Authentication credentials not provided or invalid.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        methods=["POST"],
        summary="Delete own account",
        description=(
            "Allows the currently authenticated user to permanently delete their account.\n\n"
            "⚠️ Requires the current password as a passphrase for security.\n\n"
            "**Expected payload:**\n"
            "```json\n"
            "{ \"passphrase\": \"current_password\" }\n"
            "```\n\n"
            "**Possible responses:**\n"
            "- `204 No Content`: Account successfully deleted.\n"
            "- `400 Bad Request`: Invalid or missing passphrase.\n"
            "- `401 Unauthorized`: Authentication credentials were not provided or invalid."
        ),
        request=AccountDeleteSerializer,
        responses={
            204: OpenApiResponse(description="Account successfully deleted."),
            400: OpenApiResponse(description="Invalid passphrase or input."),
        },
    )
    def post(self, request):
        serializer = AccountDeleteSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.delete()
            logger.info(
                f"[DeleteAccount] User {user.email} deleted their account.")
            return Response({'detail': 'Account successfully deleted.'}, status=status.HTTP_204_NO_CONTENT)
        logger.warning(
            f"[DeleteAccount] Validation errors: {serializer.errors}")
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
        404: OpenApiResponse(description="User not found.")
    }
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
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
    logger.warning(
        '[AdminUserView] Admin user management endpoint initialized.')

    def perform_create(self, serializer):
        user = serializer.save(is_active=True)

        return user

    def create(self, request, *args, **kwargs):
        try:
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = self.perform_create(serializer)
                logger.info(
                    f"[AdminUserView] New user registered: {user.email}")
                return Response(
                    {"message": "User registered successfully."},
                    status=status.HTTP_201_CREATED
                )
            logger.warning(
                f"[AdminUserView] Registration failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"[AdminUserView] Registration error: {e}")
            return Response({"error": "Internal server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        logger.info(f"[AdminUserView] Updating user: {kwargs.get('pk', 'Unknown')}")
        return super().update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        logger.info(
            f"[AdminUserView] Deleting user: {request.data.get('email', 'Unknown')}")
        return super().delete(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        logger.info(f"[AdminUserView] Listing users")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(
            f"[AdminUserView] Retrieving user: {kwargs.get('pk', 'Unknown')}")
        return super().retrieve(request, *args, **kwargs)


@extend_schema(
    tags=["Profile"],
    summary="Upload user profile picture",
    description=(
        "Allows an authenticated user to upload or update their profile picture.\n\n"
        "The image file must be sent as a multipart/form-data request with the key `profile_picture`."
    ),
    request=ProfilePictureSerializer,
    responses={
        200: OpenApiResponse(description="Profile picture updated successfully."),
        400: OpenApiResponse(description="Invalid image file or request data."),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
    },
)
@method_decorator(ensure_csrf_cookie, name='dispatch')
class ProfilePictureUploadView(APIView):
    """
    Upload or update the authenticated user's profile picture.

    Requires the user to be authenticated.

    Request:
        - Multipart/form-data with key `profile_picture` containing the image file.

    Responses:
        - 200 OK:
            {
                "detail": "Profile picture updated successfully."
            }
        - 400 Bad Request: Validation errors (e.g., invalid image format).
        - 401 Unauthorized: If authentication credentials are missing or invalid.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ProfilePictureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.update(request.user, serializer.validated_data)
            return Response({"detail": "Profile picture updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
