import pytest
from django.urls import reverse
from rest_framework import status
from django.core.files.uploadedfile import SimpleUploadedFile

@pytest.mark.django_db
def test_profile_upload_photo_unauthenticated(api_client, get_test_image):
    url = reverse("profile-photo-upload")
    data = {"profile_picture": get_test_image}
    response = api_client.post(url, data, format="multipart")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED