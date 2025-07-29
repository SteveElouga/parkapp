from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from .models import Vehicle, ParkingSlot, Reservation, ReservationTicket
from .serializers import (
    VehicleSerializer,
    ParkingSlotSerializer,
    ReservationSerializer,
    ReservationTicketSerializer,
)
from rest_framework.response import Response


class VehicleViewSet(viewsets.ModelViewSet):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    permission_classes = [permissions.IsAuthenticated]


class ParkingSlotViewSet(viewsets.ModelViewSet):
    queryset = ParkingSlot.objects.all()
    serializer_class = ParkingSlotSerializer
    permission_classes = [permissions.IsAuthenticated]

    # Example usage of @action decorator
    @action(detail=True, methods=["get"])
    def custom_action(self, request, pk=None):
        slot = self.get_object()
        return Response({"status": "custom action executed", "slot_id": slot.id})

    @action(detail=True, methods=["post"])
    def disable(self, request, pk=None):
        slot = self.get_object()
        try:
            slot.disable()
            return Response({"status": "Parking slot disabled successfully"})
        except ValueError as e:
            return Response({"error": str(e)}, status=400)


class ReservationViewSet(viewsets.ModelViewSet):
    queryset = Reservation.objects.all()
    serializer_class = ReservationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ReservationTicketViewSet(viewsets.ModelViewSet):
    queryset = ReservationTicket.objects.all()
    serializer_class = ReservationTicketSerializer
    permission_classes = [permissions.IsAuthenticated]
