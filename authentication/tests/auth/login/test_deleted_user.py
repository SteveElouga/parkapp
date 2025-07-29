import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_deleted_user(api_client, active_user):
    active_user.delete()
    url = reverse("login")
    response = api_client.post(
        url, {"email": active_user.email, "password": "AminaSecure456#"}, format="json"
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
