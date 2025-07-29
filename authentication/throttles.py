from rest_framework.throttling import UserRateThrottle

class LoginThrottle(UserRateThrottle):
    scope = 'login'

class PasswordChangeThrottle(UserRateThrottle):
    scope = 'password_change'

class AccountDeleteThrottle(UserRateThrottle):
    scope = 'account_delete'

class ProfilePhotoUploadThrottle(UserRateThrottle):
    scope = 'profile_photo_upload'

class RegisterThrottle(UserRateThrottle):
    scope = 'register'

class ActivationThrottle(UserRateThrottle):
    scope = 'activation'

class PasswordResetRequestThrottle(UserRateThrottle):
    scope = 'password_reset_request'