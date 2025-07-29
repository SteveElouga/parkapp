from django.contrib import admin

from .models import Vehicle, ParkingSlot, Reservation, ReservationTicket


@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ("plate_number", "model", "brand", "color", "owner", "created_at")
    search_fields = ("plate_number", "model", "brand", "owner__email")
    list_filter = ("brand", "color")


@admin.register(ParkingSlot)
class ParkingSlotAdmin(admin.ModelAdmin):
    list_display = ("code", "is_available", "location_description")
    list_filter = ("is_available",)
    search_fields = ("code", "location_description")


@admin.register(Reservation)
class ReservationAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "vehicle",
        "parking_slot",
        "start_time",
        "end_time",
        "created_at",
    )
    search_fields = ("user__email", "vehicle__plate_number", "parking_slot__code")
    list_filter = ("start_time", "end_time")


@admin.register(ReservationTicket)
class ReservationTicketAdmin(admin.ModelAdmin):
    list_display = (
        "ticket_number",
        "reservation",
        "issued_at",
        "is_paid",
        "status",
        "validated_at",
    )
    search_fields = ("ticket_number", "reservation__id", "reservation__user__email")
    list_filter = ("status", "is_paid")
