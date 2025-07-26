import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import User, ActivationCode
from django.utils import timezone


ACTIVATE_URL = reverse("activate")


@pytest.mark.django_db
def test_successful_activation(api_client, user_data):
    user_data_filtered = {
        key: value for key, value in user_data.items()
        if key != "password_confirm"
    }

    user = User.objects.create_user(**user_data_filtered)
    user.is_active = False
    user.save()
    
    code = ActivationCode.objects.create(
        user=user,
        code="123456",
        is_used=False,
        created_at=timezone.now()
    )

    response = api_client.post(ACTIVATE_URL, {"code": "123456"}, format="json")

    user.refresh_from_db()
    code.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert response.data["detail"] == "Account activated successfully."
    assert user.is_active is True
    assert code.is_used is True
