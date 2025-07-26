import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_register_missing_fields(api_client):
    url = reverse("register")
    invalid_data = {"email": "", "password": ""}

    response = api_client.post(url, invalid_data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data
    assert "password" in response.data

@pytest.mark.django_db
def test_register_weak_password(api_client, user_data):
    url = reverse("register")
    user_data["password"] = "123"

    response = api_client.post(url, user_data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "password" in response.data
