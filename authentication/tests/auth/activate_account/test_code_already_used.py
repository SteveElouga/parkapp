import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import ActivationCode


@pytest.mark.django_db
def test_activate_code_already_used(api_client, user):
    ActivationCode.objects.create(user=user, code="123457", is_used=True)
    url = reverse("activate")
    response = api_client.post(url, {"code": "123457"}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid activation code" in response.data.get("detail", "").lower()
