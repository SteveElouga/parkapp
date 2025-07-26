import pytest
from rest_framework import status
from django.urls import reverse

PASSWORD_RESET_REQUEST_URL = reverse("password_reset_request")


@pytest.mark.django_db
def test_password_reset_request_nonexistent_email(api_client):
    payload = {"email": "nobody@example.com"}
    response = api_client.post(PASSWORD_RESET_REQUEST_URL, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert response.data["detail"] == "If that email is registered, a reset link will be sent."
