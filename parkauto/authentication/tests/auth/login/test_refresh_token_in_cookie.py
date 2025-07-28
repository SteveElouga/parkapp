import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_refresh_token_in_cookie(api_client, active_user):
    url = reverse("login")
    response = api_client.post(url, {
        "email": active_user.email,
        "password": "AminaSecure456#"
    }, format="json")
    cookies = response.cookies
    assert "refresh_token" in cookies 