from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Reservation, ReservationTicket

@receiver(post_save, sender=Reservation)
def create_ticket_for_reservation(sender, instance, created, **kwargs):
    if created and not hasattr(instance, 'ticket'):
        ReservationTicket.objects.create(reservation=instance)
