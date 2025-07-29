from django.core.mail import send_mail


def send_activation_email(user):
    send_mail(
        subject="Code d’activation",
        message=f"Votre code d’activation est {user.activation_code}",
        from_email="noreply@parkauto.com",
        recipient_list=[user.email],
    )


def send_activation_sms(user):
    print(
        f"[SIMULATION SMS] Code d’activation envoyé à {user.phone}: {user.activation_code}"
    )
