import uuid
import pytz
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from datetime import date
# Create your models here.
class AccountManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        username = username
        email = self.normalize_email(email)
        user = self.model(
            username=username,
            email=email    
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, username, email, password=None):
        timezone = 'Asia/Ho_Chi_Minh'
        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.save(using=self._db)
        return user

class Account(AbstractBaseUser, PermissionsMixin):
    timezones = tuple(zip(pytz.all_timezones, pytz.all_timezones))

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=255)
    email_confirmed = models.BooleanField(default=False)
    timezone = models.CharField(max_length=52, choices=timezones, default='Asia/Ho_Chi_Minh')
    is_staff = models.BooleanField(default=True)

    objects = AccountManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str_(self):
        return self.username

class Profile(models.Model):
    username = models.OneToOneField(Account, on_delete=models.CASCADE)
    fullname = models.CharField(max_length=50)
    address = models.CharField(max_length=100)
    country = models.CharField(max_length=50)
    phone = models.CharField(max_length=12)
    date_of_birth = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.fullname

    def dictionary(self):
        dict = {
            'fullname': self.fullname,
            'date_of_birth': self.date_of_birth,
            'address': self.address,
            'country': self.country,
            'phone': self.phone
        }
        return dict
        
class AccessToken(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    value = models.CharField(max_length=255)

class Blacklist(models.Model):
    token = models.TextField()





