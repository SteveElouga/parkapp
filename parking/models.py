import qrcode
import io
from django.core.files.base import ContentFile
from django.db import models
import uuid
from django.db import transaction
from django.conf import settings

# Create your models here.
class Vehicle(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vehicles')
    plate_number = models.CharField(max_length=20, unique=True)
    model = models.CharField(max_length=100)
    brand = models.CharField(max_length=100)
    color = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.plate_number} - {self.model}"

    class Meta:
        verbose_name = 'Vehicle'
        verbose_name_plural = 'Vehicles'
        ordering = ['-created_at']




class ParkingSlot(models.Model):
    code = models.CharField(max_length=10, unique=True)
    is_available = models.BooleanField(default=True)
    location_description = models.CharField(max_length=255, blank=True)
    
    @transaction.atomic
    def disable(self):
        if self.is_available:
            self.is_available = False
            self.save()
        else:
            raise ValueError("Parking slot is already occupied.")

    def __str__(self):
        return f"Slot {self.code} - {'Available' if self.is_available else 'Occupied'}"
    
    class Meta:
        verbose_name = 'Parking Slot'
        verbose_name_plural = 'Parking Slots'
        ordering = ['code']

class Reservation(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reservations')
    vehicle = models.ForeignKey('Vehicle', on_delete=models.CASCADE)
    parking_slot = models.ForeignKey('ParkingSlot', on_delete=models.CASCADE)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.parking_slot.code} - {self.start_time.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        verbose_name = 'Reservation'
        verbose_name_plural = 'Reservations'
        ordering = ['-created_at']



class ReservationTicket(models.Model):
    reservation = models.OneToOneField('Reservation', on_delete=models.CASCADE, related_name='ticket')
    ticket_number = models.CharField(max_length=100, unique=True, editable=False)
    issued_at = models.DateTimeField(auto_now_add=True)
    is_paid = models.BooleanField(default=False)
    validated_at = models.DateTimeField(blank=True, null=True)

    class Status(models.TextChoices):
        GENERATED = 'generated', 'Généré'
        PAID = 'paid', 'Payé'
        USED = 'used', 'Utilisé'
        CANCELLED = 'cancelled', 'Annulé'

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.GENERATED
    )

    qr_code_image = models.ImageField(upload_to='tickets/qrcodes/', blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.ticket_number:
            self.ticket_number = str(uuid.uuid4()).replace("-", "").upper()[:12]

        super().save(*args, **kwargs)

        if not self.qr_code_image:
            self.generate_qr_code()

    def generate_qr_code(self):
        qr_data = f"Reservation: {self.reservation.id} | Ticket: {self.ticket_number}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        file_name = f"ticket_{self.ticket_number}.png"

        self.qr_code_image.save(file_name, ContentFile(buffer.getvalue()), save=False)
        self.save(update_fields=["qr_code_image"])

    def __str__(self):
        return f"Ticket #{self.ticket_number} – Reservation {self.reservation.id}"
    
    class Meta:
        verbose_name = 'Reservation Ticket'
        verbose_name_plural = 'Reservation Tickets'
        ordering = ['-issued_at']
