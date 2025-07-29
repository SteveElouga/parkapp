from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


# Register your models here.
@admin.register(User)
class UserAdmin(UserAdmin):
    # Affiche les colonnes principales
    list_display = (
        "email",
        "first_name",
        "last_name",
        "role",
        "is_active",
        "date_joined",
    )
    list_filter = ("role", "is_active", "is_staff", "is_superuser")

    # Organisation des champs dans la page de détail
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Informations personnelles",
            {"fields": ("first_name", "last_name", "profile_picture", "date_of_birth")},
        ),
        ("Coordonnées", {"fields": ("phone_number", "address", "city", "country")}),
        (
            "Permissions",
            {
                "fields": (
                    "role",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Dates importantes", {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2", "role"),
            },
        ),
    )

    search_fields = ("email", "first_name", "last_name")
    ordering = ("email",)
    filter_horizontal = ("groups", "user_permissions")
