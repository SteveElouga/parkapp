import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_too_weak(api_client, user_data):
    user_data["password"] = "password"
    user_data["password_confirm"] = "password"
    url = reverse("register")
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "password" in response.data
