import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_can_list_users(api_client, admin_user, user_factory):
    u1 = user_factory(email="foo@example.com", last_name="Foo", first_name="Bar", password="BarPassword123!")
    u2 = user_factory(email="bar@example.com", last_name="Bar", first_name="Baz", password="BazPassword123!")
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-list")
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    emails = [item["email"] for item in response.data["results"]] if "results" in response.data else [item["email"] for item in response.data]
    assert u1.email in emails and u2.email in emails