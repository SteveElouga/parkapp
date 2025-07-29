import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_request_invalid_email_format(api_client):
    url = reverse("password_reset_request")
    data = {"email": "not-an-email"}
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data or "detail" in response.data
