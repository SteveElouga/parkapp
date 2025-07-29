import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_delete_photo_no_photo(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("profile-photo-delete")
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "No profile picture" in response.data["message"]
