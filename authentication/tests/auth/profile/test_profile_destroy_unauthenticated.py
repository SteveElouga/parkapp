import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_destroy_unauthenticated(api_client, active_user):
    url = reverse("user-profile")
    data = {"passphrase": f"{active_user.email}_delete"}
    response = api_client.delete(url, data, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
