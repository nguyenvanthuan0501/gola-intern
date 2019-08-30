import phonenumbers
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

    def validate(self, attrs):
        if attrs['username'] == '':
            raise serializers.ValidationError('This field is required')
        else:
            account_exists = Account.objects.filter(
                username=attrs['username']).exists()
            if account_exists:
                raise serializers.ValidationError('Username already exists')
            if attrs['password'] == '':
                raise serializers.ValidationError('This field is required')
        return attrs


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
            raise serializers.ValidationError(
                'New password is the same old password')
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Confirm password not match')
        return attrs


class ProfileSerializer(serializers.Serializer):
    fullname = serializers.CharField(
        max_length=50, allow_blank=True, allow_null=True, required=False)
    address = serializers.CharField(
        max_length=100, allow_blank=True, allow_null=True, required=False)
    country = serializers.CharField(
        max_length=50, allow_blank=True, allow_null=True, required=False)
    phone = serializers.CharField(
        max_length=12, allow_blank=True, allow_null=True, required=False)
    date_of_birth = serializers.CharField(
        max_length=10, allow_blank=True, allow_null=True, required=False)

    def validate(self, attrs):
        if attrs['country'] == '':
            attrs['country'] == ''
        elif attrs['country'] not in countries:
            raise serializers.ValidationError('Invalid country')
        try:
            phone_number = phonenumbers.parse(attrs['phone'], None)
            if not phonenumbers.is_valid_number(phone_number):
                raise serializers.ValidationError('Invalid phone number')
        except:
            raise serializers.ValidationError('Invalid phone number')
        if attrs['date_of_birth'] == '':
            attrs['date_of_birth'] == ''
        else:
            try:
                datetime.strptime(attrs['date_of_birth'], '%Y-%m-%d')
            except:
                raise serializers.ValidationError('Invalid date')
        return attrs
