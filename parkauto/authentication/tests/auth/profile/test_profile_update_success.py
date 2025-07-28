import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_update_success(api_client, active_user, mailoutbox):
    api_client.force_authenticate(user=active_user)
    url = reverse("user-profile")
    data = {"first_name": "NouveauNom"}
    response = api_client.put(url, data, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert "message" in response.data
    assert "successfully" in response.data["message"]
    active_user.refresh_from_db()
    assert active_user.first_name == "NouveauNom"
    # Vérifie qu'un mail est envoyé
    assert len(mailoutbox) == 1