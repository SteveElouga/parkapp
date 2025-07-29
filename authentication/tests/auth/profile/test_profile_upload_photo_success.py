import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_upload_photo_success(api_client, active_user, get_test_image):
    api_client.force_authenticate(user=active_user)
    url = reverse("profile-photo-upload")
    data = {"profile_picture": get_test_image}
    response = api_client.post(url, data, format="multipart")
    print(response.data)
    assert response.status_code == status.HTTP_200_OK
    assert "successfully" in response.data["message"]
