from rest_framework.throttling import UserRateThrottle

class PasswordChangeThrottle(UserRateThrottle):
    scope = 'password_change'

class AccountDeleteThrottle(UserRateThrottle):
    scope = 'account_delete'

class ProfilePhotoUploadThrottle(UserRateThrottle):
    scope = 'profile_photo_upload'