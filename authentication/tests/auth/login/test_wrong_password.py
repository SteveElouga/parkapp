import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_wrong_password(api_client, active_user):
    url = reverse("login")
    creds = {"email": active_user.email, "password": "AminaSeure456#"}
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
