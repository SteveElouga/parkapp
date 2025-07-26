import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch
from rest_framework_simplejwt.exceptions import TokenError

REFRESH_URL = reverse("token_refresh")

@pytest.mark.django_db
def test_refresh_missing_cookie(api_client):
    response = api_client.post(
        REFRESH_URL,
        HTTP_X_CSRFTOKEN="valid-csrf-token"
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "detail" in response.data
    assert response.data["detail"] == "Refresh token not found in cookies."
