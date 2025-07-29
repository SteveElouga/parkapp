import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import ActivationCode
from datetime import timedelta
from django.utils import timezone


@pytest.mark.django_db
def test_activate_code_expired(api_client, user):
    activation = ActivationCode.objects.create(user=user, code="123458")
    # Simule l’expiration du code
    activation.created_at = timezone.now() - timedelta(days=2)
    activation.save()
    url = reverse("activate")
    response = api_client.post(url, {"code": "123458"}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "expired" in response.data.get("detail", "").lower()
