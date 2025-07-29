import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_request_inactive_user(api_client, user, mailoutbox):
    url = reverse("password_reset_request")
    data = {"email": user.email}
    response = api_client.post(url, data, format="json")
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]
    assert (
        len(mailoutbox) == 0
    )  # ou 1 selon la politique, mais souvent on ne mail pas l'utilisateur inactif
