import pytest
from django.urls import reverse
from rest_framework import status

from authentication.models import User

ADMIN_URL = reverse("users-list")


@pytest.mark.django_db
def test_create_user_as_admin(api_client, admin_user):
    user_data = {
        "email": "lo.camara@example.com",
        "username": "moussa_c_gn",
        "password": "MoussaSafe789!",
        "password_confirm": "MoussaSafe789!",
    }
    user_data['is_active'] = True
    user_data['is_staff'] = True
    user_data['role'] = 'admin'

    api_client.force_authenticate(user=admin_user)
    response = api_client.post(ADMIN_URL, user_data, format="json")
    
    user = User.objects.filter(email=user_data['email']).get()

    assert response.status_code == status.HTTP_201_CREATED
    assert User.objects.filter(email=user_data['email']).exists()
    assert user.email == user_data['email']
    assert user.is_active is True
    assert user.is_staff is True
    assert user.role == 'admin'
