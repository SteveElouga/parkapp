import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import User, ActivationCode
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch


ACTIVATE_URL = reverse("activate")

@pytest.mark.django_db
@patch("authentication.views.ActivationCode.is_expired", return_value=True)
def test_expired_code(mock_is_expired, api_client, user_data):
    user_data_filtered = {
        key: value for key, value in user_data.items()
        if key != "password_confirm"
    }

    user = User.objects.create_user(**user_data_filtered)
    user.is_active = False
    user.save()
    
    ActivationCode.objects.create(
        user=user,
        code="654321",
        is_used=False,
        created_at=timezone.now() - timedelta(hours=2)
    )

    response = api_client.post(ACTIVATE_URL, {"code": "654321"}, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["detail"] == "The code has expired."
    mock_is_expired.assert_called_once()
