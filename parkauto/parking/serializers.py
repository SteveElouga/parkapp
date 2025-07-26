from django.conf import settings
from rest_framework import serializers
from django.contrib.auth import get_user_model

from authentication.serializers import UserSerializer
from .models import Vehicle, ParkingSlot, Reservation, ReservationTicket

User = get_user_model()

class VehicleSerializer(serializers.ModelSerializer):
    """
    Serializer for representing and managing `Vehicle` instances.

    This serializer includes full owner information in read operations 
    and expects the owner's ID (`owner_id`) for write operations.

    Fields:
        - id (read-only): Unique identifier of the vehicle.
        - owner (read-only): Full nested user representation.
        - owner_id (write-only): ID of the vehicle's owner.
        - plate_number: Vehicle's license plate.
        - model: Vehicle's model.
        - brand: Vehicle's brand name.
        - color: Vehicle color.
        - created_at (read-only): Timestamp when the vehicle was registered.
    """
    
    owner = UserSerializer(read_only=True)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='owner', write_only=True
    )

    class Meta:
        model = Vehicle
        fields = ['id', 'owner', 'owner_id', 'plate_number', 'model', 'brand', 'color', 'created_at']
        read_only_fields = ['id', 'owner', 'created_at']

class ParkingSlotSerializer(serializers.ModelSerializer):
    """
    Serializer for representing and managing `ParkingSlot` instances.

    Fields:
        - id (read-only): Unique identifier of the parking slot.
        - code: Unique alphanumeric code identifying the slot.
        - is_available: Boolean indicating slot availability.
        - location_description: Optional description of the slot location.
    """
    
    class Meta:
        model = ParkingSlot
        fields = ['id', 'code', 'is_available', 'location_description']
        read_only_fields = ['id']

class ReservationSerializer(serializers.ModelSerializer):
    """
    Serializer for handling `Reservation` instances between users, vehicles, and parking slots.

    This serializer uses nested representations for read operations and expects corresponding IDs for write operations.

    Fields:
        - id (read-only): Unique identifier of the reservation.
        - user (read-only): Full nested user information.
        - user_id (write-only): ID of the user who made the reservation.
        - vehicle (read-only): Full nested vehicle information.
        - vehicle_id (write-only): ID of the reserved vehicle.
        - parking_slot (read-only): Full nested parking slot information.
        - parking_slot_id (write-only): ID of the reserved parking slot.
        - start_time: Timestamp marking the start of the reservation.
        - end_time: Timestamp marking the end of the reservation.
        - created_at (read-only): Timestamp when the reservation was created.
    """
    
    user = UserSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='user', write_only=True
    )
    vehicle = VehicleSerializer(read_only=True)
    vehicle_id = serializers.PrimaryKeyRelatedField(
        queryset=Vehicle.objects.all(), source='vehicle', write_only=True
    )
    parking_slot = ParkingSlotSerializer(read_only=True)
    parking_slot_id = serializers.PrimaryKeyRelatedField(
        queryset=ParkingSlot.objects.all(), source='parking_slot', write_only=True
    )

    class Meta:
        model = Reservation
        fields = [
            'id', 'user', 'user_id', 'vehicle', 'vehicle_id',
            'parking_slot', 'parking_slot_id',
            'start_time', 'end_time', 'created_at'
        ]
        read_only_fields = ['id', 'user', 'vehicle', 'parking_slot', 'created_at']

class ReservationTicketSerializer(serializers.ModelSerializer):
    """
    Serializer for managing `ReservationTicket` instances linked to reservations.

    This serializer includes a nested reservation for read operations and expects 
    the reservation ID for write operations.

    Fields:
        - id (read-only): Unique identifier of the ticket.
        - reservation (read-only): Full nested reservation information.
        - reservation_id (write-only): ID of the associated reservation.
        - ticket_number (read-only): Automatically generated unique ticket number.
        - issued_at (read-only): Timestamp when the ticket was issued.
        - is_paid: Boolean indicating whether the ticket has been paid.
        - status: Current status of the reservation ticket (e.g., pending, validated).
        - validated_at: Timestamp when the ticket was validated.
        - qr_code_image (read-only): Base64 or image URL of the generated QR code.
    """
    
    reservation = ReservationSerializer(read_only=True)
    reservation_id = serializers.PrimaryKeyRelatedField(
        queryset=Reservation.objects.all(), source='reservation', write_only=True
    )

    class Meta:
        model = ReservationTicket
        fields = [
            'id', 'reservation', 'reservation_id', 'ticket_number',
            'issued_at', 'is_paid', 'status', 'validated_at', 'qr_code_image'
        ]
        read_only_fields = ['id', 'ticket_number', 'issued_at', 'qr_code_image']