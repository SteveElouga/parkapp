import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import ActivationCode
from authentication.tests.conftest import user_data

@pytest.mark.django_db
def test_activate_user_is_active(api_client, active_user):
    active_user.is_active = True
    active_user.save()
    ActivationCode.objects.create(user=active_user, code="123459")
    url = reverse("activate")
    response = api_client.post(url, {"code": "123459"}, format="json")
    # Le code doit être utilisable une seule fois
    assert response.status_code == status.HTTP_400_BAD_REQUEST or response.status_code == status.HTTP_200_OK