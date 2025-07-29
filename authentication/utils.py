import random
from django.core.mail import send_mail
from decouple import config

from_email_send = config("DEFAULT_FROM_EMAIL", default="noreply@tonsite.com")


def generate_activation_code(length=6):
    return "".join(random.choices("0123456789", k=length))


def clean_strings(data, fields):
    """
    Nettoie les champs string en enlevant les espaces au début/fin.
    Peut être utilisé dans n'importe quel serializer.
    """
    for field in fields:
        if field in data and isinstance(data[field], str):
            data[field] = data[field].strip()
    return data


def send_reset_email(user, reset_link):
    subject = "Your password reset request"
    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>We have received a request to reset your password.</p>
        <p>👉 To set a new password, please click the link below:</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <p>⚠️ This link is valid for a limited time only.</p>
        <p>If you did not request this, you can safely ignore this message.</p>
        <br>
        <p>Best regards,<br>The support team<br><a href="mailto:noreply@tonsite.com">noreply@tonsite.com</a></p>
    </body>
    </html>
    """
    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def send_confirmation_reset_password_email(user, login_url):
    subject = "Password Reset Confirmation"
    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>Your password has been successfully reset.</p>
        <p>You can now log in using your new password:</p>
        <p>👉 <a href="{login_url}">{login_url}</a></p>
        <p>If you did not request this change, please contact our support team immediately.</p>
        <br>
        <p>Best regards,<br>The support team<br><a href="mailto:noreply@tonsite.com">noreply@tonsite.com</a></p>
    </body>
    </html>
    """

    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def send_activation_email_with_code(user, activation_code):
    subject = "Your activation code for ParkAuto"
    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>Thank you for registering.</p>
        <p>🎉 Here is your activation code: <strong>{activation_code}</strong></p>
        <p>Please enter this code in the app to complete the activation of your account.</p>
        <p>⚠️ This code is for one-time use only and will expire in a few minutes.</p>
        <p>If you did not initiate this registration, you can safely ignore this message.</p>
        <br>
        <p>Best regards,<br>The support team<br><a href="mailto:noreply@tonsite.com">noreply@tonsite.com</a></p>
    </body>
    </html>
    """
    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def send_account_activated_email(user, login_url):
    subject = "Your account has been successfully activated"

    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>Your account has been successfully activated. 🎉</p>
        <p>You can now log in using your credentials:</p>
        <p>👉 <a href="{login_url}">{login_url}</a></p>
        <p>If you did not request this activation, please contact our support team.</p>
        <br>
        <p>Best regards,<br>The Support Team<br><a href="mailto:noreply@yourdomain.com">noreply@yourdomain.com</a></p>
    </body>
    </html>
    """

    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def send_password_change_email(user):
    subject = "Your password has been changed successfully"
    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>🔒 Your password has been successfully changed.</p>
        <p>If you did not perform this action, please contact our support team immediately to secure your account.</p>
        <br>
        <p>Best regards,<br>The support team<br><a href="mailto:noreply@tonsite.com">noreply@tonsite.com</a></p>
    </body>
    </html>
    """

    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def send_account_updated_email(user):
    subject = "Your account has been updated successfully"
    html_message = f"""
    <html>
    <body>
        <p>Hello {user.first_name} {user.last_name},</p>
        <p>✅ Your account information has been successfully updated.</p>
        <p>If you did not perform this action, please contact our support team immediately.</p>
        <br>
        <p>Best regards,<br>The support team<br><a href="mailto:noreply@tonsite.com">noreply@tonsite.com</a></p>
    </body>
    </html>
    """

    from_email = from_email_send
    send_mail(
        subject,
        "",
        from_email,
        [user.email],
        fail_silently=False,
        html_message=html_message,
    )


def validate_profile_picture(image):
    """
    Valide l'image de profil.
    Vérifie la taille maximale (2 Mo) et le type MIME (doit être une image).
    :param image: Fichier image à valider.
    :raises Exception: Si l'image est trop volumineuse ou de type incorrect.
    :return: L'image validée.
    """
    # Taille max 2 Mo
    if image.size > 2 * 1024 * 1024:
        raise Exception("Image trop volumineuse (>2 Mo).")
    # Type mime
    if hasattr(image, "content_type") and not image.content_type.startswith("image/"):
        raise Exception("Le fichier doit être une image.")
    # Optionnel: résolution minimale/maximale, format autorisé
    return image
