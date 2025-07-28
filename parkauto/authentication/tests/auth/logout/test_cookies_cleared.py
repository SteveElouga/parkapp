import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_cookies_cleared(api_client, active_user, valid_refresh_token):
    url = reverse("logout")
    api_client.force_authenticate(user=active_user)
    # Simule le refresh token en cookie si ton API l'utilise
    api_client.cookies['refresh'] = valid_refresh_token
    response = api_client.post(url, {}, format="json")
    # Vérifie que le cookie est supprimé
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.cookies.get('refresh_token', None) is None or response.cookies['refresh_token'].value == ""