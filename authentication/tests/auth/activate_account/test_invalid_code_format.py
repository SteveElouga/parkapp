import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
@pytest.mark.parametrize("bad_code", ["abc123", "12", "1234567", ""])
def test_activate_invalid_code_format(api_client, bad_code):
    url = reverse("activate")
    response = api_client.post(url, {"code": bad_code}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        "code" in response.data or "invalid" in response.data.get("detail", "").lower()
    )
