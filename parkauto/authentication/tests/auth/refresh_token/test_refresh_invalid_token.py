import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch
from rest_framework_simplejwt.exceptions import TokenError

REFRESH_URL = reverse("token_refresh")

@pytest.mark.django_db
@patch("authentication.views.CustomTokenRefreshView.get_serializer")
def test_refresh_invalid_token(mock_get_serializer, api_client, valid_refresh_token):
    api_client.cookies["refresh_token"] = valid_refresh_token

    # Simule une erreur TokenError lors de la validation
    mock_serializer = mock_get_serializer.return_value
    mock_serializer.is_valid.side_effect = TokenError("Token is invalid")

    response = api_client.post(
        REFRESH_URL,
        HTTP_X_CSRFTOKEN="valid-csrf-token"
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
    assert response.data["detail"] == "Token is invalid"