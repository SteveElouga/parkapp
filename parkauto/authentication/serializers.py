import re
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator

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
            'email', 'username', 'password', 'password_confirm',
            'first_name', 'last_name', 'role', 'phone_number',
            'address', 'city', 'country', 'profile_picture', 'date_of_birth'
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


class ProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving and updating the authenticated user's profile.

    Fields:
        - id: User ID (read-only).
        - email: Email (read-only).
        - username, first_name, last_name, etc.: Editable profile information.
    """

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'role', 'phone_number', 'address', 'city',
            'country', 'profile_picture', 'date_of_birth'
        ]
        read_only_fields = ['id', 'email']


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer to handle user password changes securely.

    Validates:
        - Old password matches the current user password.
        - New password meets complexity rules.
        - New password and confirmation match.

    Fields:
        - old_password: Current password of the user.
        - new_password: New desired password (write-only).
        - confirm_new_password: Confirmation of the new password.
    """

    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(
        write_only=True, validators=[validate_password])
    confirm_new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password incorrect.")
        return value

    def validate_new_password(self, value):
        if not re.match(password_regex, value):
            raise serializers.ValidationError(
                "The password must contain at least 8 characters, "
                "including one lowercase, one uppercase, one number, one special character, "
                "and must not contain spaces."
            )
        password_validation.validate_password(value)
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_new_password']:
            raise serializers.ValidationError({
                "confirm_new_password": "The passwords do not match."
            })
        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()

        # Invalider les anciens tokens si nécessaire
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
        tokens = OutstandingToken.objects.filter(user=user)
        for token in tokens:
            try:
                BlacklistedToken.objects.get_or_create(token=token)
            except Exception:
                continue

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
            'id', 'email', 'username', 'first_name', 'last_name',
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


class AccountDeleteSerializer(serializers.Serializer):
    """
    Serializer for confirming account deletion by the authenticated user.

    Fields:
        - passphrase: Required to confirm account deletion. Must be in the form `<email>_delete`.
    """

    passphrase = serializers.CharField(write_only=True)

    def validate_passphrase(self, value):
        user = self.context['request'].user
        if not (value == f'{user.email}_delete'):
            raise serializers.ValidationError("Incorrect passphrase.")
        return value


class ProfilePictureSerializer(serializers.Serializer):
    """
    Serializer for uploading or updating a user's profile picture.

    Fields:
        - profile_picture (ImageField): The image file to set as the user's profile picture.

    Methods:
        - update(instance, validated_data): Updates the `profile_picture` field of the given user instance
          with the validated image file and saves the instance.

    Usage:
        Used to validate and save a new profile picture uploaded by the user.
    """

    profile_picture = serializers.ImageField()

    def update(self, instance, validated_data):
        instance.profile_picture = validated_data.get('profile_picture')
        instance.save()
        return instance
