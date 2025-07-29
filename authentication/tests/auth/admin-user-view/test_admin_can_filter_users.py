import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_can_filter_users(api_client, admin_user, user_factory):
    user_factory(email="active@example.com", is_active=True, role="client", password="Testpass123!", first_name='Active')
    user_factory(email="inactive@example.com", is_active=False, role="client", password="Testpass123!", first_name='Inactive')
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-list")
    response = api_client.get(url, {"first_name": 'Active'})
    print('Response data:', response.data)
    assert response.status_code == status.HTTP_200_OK
    emails = [u["email"] for u in response.data.get("results", response.data)]
    assert "active@example.com" in emails
    assert "inactive@example.com" not in emails

    # Filter by role
    response = api_client.get(url, {"role": "client"})
    emails = [u["email"] for u in response.data.get("results", response.data)]
    assert "active@example.com" in emails and "inactive@example.com" in emails