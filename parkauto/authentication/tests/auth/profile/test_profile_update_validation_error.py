import pytest
from django.urls import reverse
from rest_framework import status

PROFILE_URL = reverse("profile")


@pytest.mark.django_db
def test_profile_update_validation_error(api_client, active_user):

    api_client.force_authenticate(user=active_user)

    invalid_payload = {
        "date_of_birth": "invalid-date",
    }

    response = api_client.put(PROFILE_URL, invalid_payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "date_of_birth" in response.data
