import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_too_short(api_client, active_user):
    creds = {"email": active_user.email, "password": "123"}
    url = reverse("login")
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
