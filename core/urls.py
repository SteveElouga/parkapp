"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from rest_framework import routers
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from parking.views import (
    ParkingSlotViewSet,
    ReservationTicketViewSet,
    ReservationViewSet,
    VehicleViewSet,
)
from authentication.views import (
    ActivateAccountView,
    AdminUserView,
    CustomTokenRefreshView,
    GoogleSSOLoginView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    LoginView,
    LogoutView,
    UserProfileViewSet,
    GithubSSOLoginView,
)
from django.conf.urls.static import static

# Create a router and register our viewsets with it
router = routers.SimpleRouter()
user_profile = UserProfileViewSet.as_view(
    {
        "get": "retrieve",
        "put": "update",
        "delete": "destroy",
    }
)

router.register("vehicles", VehicleViewSet, basename="vehicle")
router.register("parking-slots", ParkingSlotViewSet, basename="parking-slot")
router.register("reservations", ReservationViewSet, basename="reservation")
router.register(
    "reservation-tickets", ReservationTicketViewSet, basename="reservation-ticket"
)
router.register("users", AdminUserView, basename="users")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api-auth/", include("rest_framework.urls")),
    path("api/", include(router.urls)),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/swagger/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/docs/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"
    ),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/login/", LoginView.as_view(), name="login"),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("api/activate/", ActivateAccountView.as_view(), name="activate"),
    path(
        "api/password-reset-request/",
        PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "api/password-reset-confirm/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("profile/", user_profile, name="user-profile"),
    path(
        "profile/change-password/",
        UserProfileViewSet.as_view({"post": "change_password"}),
        name="change-password",
    ),
    path(
        "profile/upload-photo/",
        UserProfileViewSet.as_view({"post": "upload_photo"}),
        name="profile-photo-upload",
    ),
    path(
        "profile/delete-photo/",
        UserProfileViewSet.as_view({"delete": "delete_photo"}),
        name="profile-photo-delete",
    ),
    path("auth/google/", GoogleSSOLoginView.as_view(), name="google-sso-login"),
    path("auth/github/", GithubSSOLoginView.as_view(), name="github-sso-login"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
