from datetime import datetime
from django.contrib.auth import authenticate
from .models import Account, Profile
from rest_framework import serializers
from iso3166 import countries

class AuthenticateAccountSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=32)

class AccountCreateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50, allow_blank=True)
    email = serializers.EmailField(allow_blank=True)
    password = serializers.CharField(max_length=32, allow_blank=True)
    
    def validate_username(self, value):
        if value == '':
            raise serializers.ValidationError('This field is required')
        else:
            account = Account.objects.all()
            if value in [user.username for user in account]:
                raise serializers.ValidationError('Username already exists')
        return value

    def validate_password(self, value):
        if value == '':
            raise serializers.ValidationError('This field is required')
        return value
    
class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=255)

class RevokeSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=255)

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=32)
    password = serializers.CharField(max_length=32)
    confirmed_password = serializers.CharField(max_length=32)

    def validate(self, attrs):
        if attrs['current_password'] == attrs['password']:
            raise serializers.ValidationError('New password is the same old password')
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Confirm password not match')
        return attrs

class ProfileSerializer(serializers.Serializer):
    fullname = serializers.CharField(max_length=50, allow_blank=True)
    address = serializers.CharField(max_length=100, allow_blank=True)
    country = serializers.CharField(max_length=50, allow_blank=True)
    phone = serializers.CharField(max_length=12, allow_blank=True)
    date_of_birth = serializers.CharField(max_length=10, allow_blank=True)

    def validate_country(self, value):
        if value not in countries:
            raise serializers.ValidationError('Invalid country')
        return value
    
    def validate_phone(self, value):
        if len(value) == 10 or len(value) == 12:
            try:
                phone_number = value
            except:
                raise serializers.ValidationError('Invalid phone number')
        else:
            raise serializers.ValidationError('Invalid phone number')
        return value 

    def validate_date_of_birth(self, value):
        if value == '':
            return value
        else:
            try:
                datetime.strptime(value, '%Y-%m-%d')
            except:
                raise serializers.ValidationError('Invalid date')
            return value