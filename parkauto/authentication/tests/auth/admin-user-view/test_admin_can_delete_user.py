import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_can_delete_user(api_client, admin_user, user_factory, django_user_model):
    user = user_factory(email="deleteme@example.com", password="Testpass123!")
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-detail", args=[user.pk])
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not django_user_model.objects.filter(pk=user.pk).exists()