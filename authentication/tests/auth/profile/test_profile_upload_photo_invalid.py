import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_upload_photo_invalid(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("profile-photo-upload")
    data = {}
    response = api_client.post(url, data, format="multipart")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "profile_picture" in response.data