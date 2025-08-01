import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_register_password_mismatch(api_client, user_data):
    user_data["password_confirm"] = "WrongPassword123!"

    url = reverse("register")
    response = api_client.post(url, user_data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "password_confirm" in response.data
