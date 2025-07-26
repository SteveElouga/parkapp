import pytest
from django.urls import reverse
from rest_framework import status

PROFILE_URL = reverse("profile")


@pytest.mark.django_db
def test_profile_update_success(api_client, active_user):

    api_client.force_authenticate(user=active_user)

    payload = {
        "first_name": "NouveauPrénom",
        "last_name": "NouveauNom",
        "phone_number": "+221770000999"
    }

    response = api_client.put(PROFILE_URL, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert response.data["message"] == "Profile updated successfully."

    active_user.refresh_from_db()
    assert active_user.first_name == payload["first_name"]
    assert active_user.last_name == payload["last_name"]
    assert active_user.phone_number == payload["phone_number"]
