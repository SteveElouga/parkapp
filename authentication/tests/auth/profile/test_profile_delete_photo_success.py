import pytest
from django.urls import reverse
from rest_framework import status
from django.core.files.uploadedfile import SimpleUploadedFile


@pytest.mark.django_db
def test_profile_delete_photo_success(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    # Ajoute une photo avant suppression
    active_user.profile_picture = SimpleUploadedFile(
        "photo.jpg", b"file_content", content_type="image/jpeg"
    )
    active_user.save()
    url = reverse("profile-photo-delete")
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_200_OK
    assert "successfully" in response.data["message"]
