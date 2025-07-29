import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_response_content(api_client, active_user):
    url = reverse("login")
    response = api_client.post(
        url, {"email": active_user.email, "password": "AminaSecure456#"}, format="json"
    )
    assert "access_token" in response.data
    assert "user" in response.data
    assert "refresh" not in response.data
