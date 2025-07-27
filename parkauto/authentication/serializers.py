import re
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator

from authentication.utils import validate_profile_picture

User = get_user_model()
password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])([^\s]{8,})$'


class ActivationSerializer(serializers.Serializer):
    """
    Serializer used to activate a user account via a 6-digit code.

    Fields:
        - code: The activation code received by the user (email/SMS).
    """

    code = serializers.CharField()


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Validates and creates a new user instance with the required fields.
    Enforces password complexity and match confirmation.

    Fields:
        - email: Email address (required).
        - username: Unique username.
        - password: User password (write-only, validated).
        - password_confirm: Confirmation of the password.
        - first_name, last_name, phone_number, etc.: Optional profile fields.
    """

    password = serializers.CharField(
        write_only=True, min_length=8, validators=[
            RegexValidator(
                regex=password_regex,
                message="Password must include at least one uppercase letter, one lowercase letter, one digit, one special character, and must not contain spaces."
            )
        ]
    )
    password_confirm = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'role', 'phone_number',
            'address', 'city', 'country', 'date_of_birth'
        ]

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError(
                {"password_confirm": "The passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    """
    General-purpose serializer for full user representation.

    Suitable for read-only use in nested serializers (e.g., vehicles, reservations).

    Fields:
        - id, email, username, full name
        - profile-related fields
        - is_active: Whether the user is active.
        - date_joined: Account creation date.
    """

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name',
            'role', 'phone_number', 'address', 'city', 'country',
            'profile_picture', 'date_of_birth', 'is_active', 'date_joined'
        ]


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer.

    Extends the default token response by adding user profile data to the payload.

    Returns:
        - access: JWT access token.
        - refresh: JWT refresh token.
        - user: Nested dictionary containing key profile information.
    """

    def validate(self, attrs):
        data = super().validate(attrs)
        data.update({
            'user': {
                'id': self.user.id,
                'email': self.user.email,
                'role': self.user.role,
                'first_name': self.user.first_name or '',
                'last_name': self.user.last_name or '',
                'phone_number': self.user.phone_number or '',
                'address': self.user.address or '',
                'city': self.user.city or '',
                'country': self.user.country or '',
                'profile_picture': self.user.profile_picture.url if self.user.profile_picture else None,
            }
        })
        return data


class LogoutSerializer(serializers.Serializer):
    """
    Serializer to blacklist a refresh token upon logout.

    Fields:
        - refresh: The refresh token to invalidate.
    """

    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except Exception:
            raise serializers.ValidationError("Invalid or expired token.")


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for initiating password reset via email.

    Fields:
        - email: Registered email address of the user.
    """

    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for setting a new password after password reset request.

    Fields:
        - token: UUID used to identify the password reset session.
        - new_password: New password (validated).
        - new_password_confirm: Confirmation of the new password.
    """

    token = serializers.UUIDField()
    new_password = serializers.CharField(
        min_length=8, max_length=128, write_only=True)
    new_password_confirm = serializers.CharField(
        min_length=8, max_length=128, write_only=True)

    def validate_new_password(self, value):
        if not re.match(password_regex, value):
            raise serializers.ValidationError(
                "The password must contain at least 8 characters, "
                "including one lowercase, one uppercase, one number, one special character, "
                "and must not contain spaces."
            )
        password_validation.validate_password(value)
        return value

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password_confirm": "The passwords do not match."
            })
        return data

class ProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for displaying and updating user profile.

    - Shows all profile fields, including profile picture (read-only).
    - Allows partial update of personal information.
    - The 'profile_picture' field is read-only and can only be updated via a dedicated action.
    - Validates phone number format.
    """

    profile_picture = serializers.ImageField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name',
            'role', 'phone_number', 'address', 'city',
            'country', 'profile_picture', 'date_of_birth'
        ]
        read_only_fields = ['id', 'email', 'profile_picture']

    def validate_phone_number(self, value):
        """
        Verifies the format of the phone number (should be international format +XXXXXXXXXXX).
        """
        if value and not re.match(r'^\+?\d{7,15}$', value):
            raise serializers.ValidationError("Invalid phone number format.")
        return value

    def update(self, instance, validated_data):
        """
        Updates user profile fields except profile picture.
        """
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for secure password change.

    - Checks the old password.
    - Enforces strong validation of the new password (complexity, uniqueness, etc.).
    - Checks matching of new password and its confirmation.
    - Blacklists previous JWT tokens after change.
    """
    old_password = serializers.CharField(
        write_only=True,
        help_text="User's current password."
    )
    new_password = serializers.CharField(
        write_only=True,
        help_text="New password, must meet security constraints.",
        validators=[
            RegexValidator(
                regex=password_regex,
                message="Password must include at least one uppercase letter, one lowercase letter, one digit, one special character, and must not contain spaces."
            ),
            password_validation.validate_password
        ]
    )
    confirm_new_password = serializers.CharField(
        write_only=True,
        help_text="Confirmation of the new password."
    )

    def validate_old_password(self, value):
        """
        Checks that the provided old password is correct.
        """
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate(self, attrs):
        """
        Checks that new passwords match and are different from the old password.
        """
        if attrs['new_password'] != attrs['confirm_new_password']:
            raise serializers.ValidationError({
                "confirm_new_password": "Passwords do not match."
            })
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError({
                "new_password": "New password must be different from the old password."
            })
        return attrs

    def save(self, **kwargs):
        """
        Updates the user's password and blacklists all previous JWT tokens.
        """
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()

        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
        tokens = OutstandingToken.objects.filter(user=user)
        for token in tokens:
            try:
                BlacklistedToken.objects.get_or_create(token=token)
            except Exception:
                continue
        return user

class AccountDeleteSerializer(serializers.Serializer):
    """
    Serializer for user account deletion.

    - Checks the passphrase (format: <email>_delete) as strong confirmation.
    - Can be extended with password check.
    """
    passphrase = serializers.CharField(
        write_only=True,
        help_text="Confirmation phrase (<email>_delete) required to delete the account."
    )

    def validate_passphrase(self, value):
        """
        Checks that the entered passphrase matches the expected one.
        """
        user = self.context['request'].user
        expected = f"{user.email}_delete"
        if value != expected:
            raise serializers.ValidationError("Incorrect passphrase.")
        return value

class ProfilePictureSerializer(serializers.Serializer):
    """
    Serializer for uploading user profile picture.

    - Validates maximum size (2MB) and MIME type (must be an image).
    - Can be extended with resolution or format constraints.
    """
    profile_picture = serializers.ImageField(
        help_text="Image file for profile picture (max 2MB)."
    )

    def validate_profile_picture(self, value):
        """
        Validates the size and type of the image file.
        """
        return validate_profile_picture(value)
    """
    Serializer pour l'upload de la photo de profil utilisateur.

    - Valide la taille maximale (2 Mo) et le type MIME (doit être une image).
    - Peut être enrichi avec des contraintes de résolution ou de format.
    """
    profile_picture = serializers.ImageField(help_text="Image file for profile picture (max 2MB).")

    def validate_profile_picture(self, value):
        """
        Valide la taille et le type du fichier image.
        """
        return validate_profile_picture(value)