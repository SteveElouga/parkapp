import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_change_password_success(api_client, active_user, mailoutbox):
    api_client.force_authenticate(user=active_user)
    url = reverse("change-password")
    data = {
        "old_password": "AminaSecure456#",
        "new_password": "NewStrongPassword123!",
        "confirm_new_password": "NewStrongPassword123!",
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert "successfully" in response.data["message"]
    # Vérifie qu'un mail a été envoyé
    assert len(mailoutbox) == 1
