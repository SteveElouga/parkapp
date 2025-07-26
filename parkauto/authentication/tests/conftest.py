from authentication.models import PasswordResetToken
import pytest
from authentication.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user_data():
    return {
        "email": "amina.ndiaye@example.com",
        "username": "amina221",
        "password": "AminaSecure456#",
        "password_confirm": "AminaSecure456#",
        "role": "client",
        "phone_number": "+221770000111",
        "address": "45 avenue Léopold Sédar Senghor",
        "city": "Dakar",
        "country": "Sénégal",
        "first_name": "Amina",
        "last_name": "Ndiaye",
        "date_of_birth": "1995-03-12"
    }


@pytest.fixture
def active_user(user_data):
    user_data_filtered = {
        key: value for key, value in user_data.items()
        if key != "password_confirm"
    }

    user = User.objects.create_user(**user_data_filtered)
    user.is_active = True
    user.save()
    return user

@pytest.fixture
def admin_user(active_user):
    active_user.is_staff = True
    active_user.is_superuser = True
    active_user.role = "admin"
    active_user.save()
    return active_user

@pytest.fixture
def valid_refresh_token(active_user):

    refresh = RefreshToken.for_user(active_user)
    return str(refresh)


@pytest.fixture
def valid_reset_token(active_user):
    return PasswordResetToken.objects.create(user=active_user)
