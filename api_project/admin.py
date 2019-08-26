from django.contrib import admin
from .models import Account, Profile, AccessToken
# Register your models here.
class AccountManager(admin.ModelAdmin):
     list_display = ['uuid', 'username', 'password', 'email', 'email_confirmed', 'timezone']

admin.site.register(Account, AccountManager)
admin.site.register(Profile)
admin.site.register(AccessToken)