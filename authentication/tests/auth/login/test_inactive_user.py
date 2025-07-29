import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_inactive_user(api_client, user):
    user.is_active = False
    user.save()
    url = reverse("login")
    response = api_client.post(
        url, {"email": user.email, "password": "AminaSecure456#"}, format="json"
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
