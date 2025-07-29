import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import ActivationCode


@pytest.mark.django_db
def test_activate_success(api_client, user):
    activation = ActivationCode.objects.create(user=user, code="123456")
    url = reverse("activate")
    response = api_client.post(url, {"code": "123456"}, format="json")
    user.refresh_from_db()
    activation.refresh_from_db()
    assert response.status_code == status.HTTP_200_OK
    assert user.is_active
    assert activation.is_used
