import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_delete_photo_unauthenticated(api_client):
    url = reverse("profile-photo-delete")
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
