import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_already_blacklisted(api_client, blacklisted_refresh_token, active_user):
    url = reverse("logout")
    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = blacklisted_refresh_token
    response = api_client.post(url, {}, format="json")
    # Selon ton API, ça peut être 400 ou 200, mais le message doit être clair
    assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK]
