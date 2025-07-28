import pytest
from django.urls import reverse
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()

@pytest.mark.django_db
def test_login_success(api_client, active_user):
    url = reverse("login")
    response = api_client.post(url, {
        "email": active_user.email,
        "password": "AminaSecure456#"
    }, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.data
    assert "user" in response.data