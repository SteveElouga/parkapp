import pytest
from rest_framework import status
from django.urls import reverse
from unittest.mock import patch

PASSWORD_RESET_REQUEST_URL = reverse("password_reset_request")


@pytest.mark.django_db
def test_password_reset_request_success(api_client, active_user):
    payload = {"email": active_user.email}

    with patch("authentication.views.send_reset_email") as mocked_send:
        response = api_client.post(PASSWORD_RESET_REQUEST_URL, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert response.data["detail"] == "If that email is registered, a reset link will be sent."
    mocked_send.assert_called_once()
