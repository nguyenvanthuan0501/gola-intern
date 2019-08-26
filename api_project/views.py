import json
import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import HttpResponse
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_201_CREATED, HTTP_200_OK, HTTP_404_NOT_FOUND, HTTP_202_ACCEPTED
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.contrib.auth.hashers import make_password
from oauth2_provider.models import AccessToken as AccesssTokenOATH
from oauthlib import common
from . import serializers
from datetime import timedelta, datetime, timezone
from .tokens import account_activation_token
from .models import Account, Profile, AccessToken, Blacklist
# Create your views here.
class AccountCreateAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer_class = serializers.AccountCreateSerializer(data=request.data)
        if serializer_class.is_valid():
            username = serializer_class.data.get('username')
            email = serializer_class.data.get('email')
            password = serializer_class.data.get('password')
            account = Account()
            account.username = username
            account.email = email
            account.password = make_password(password)
            account.save()
            return Response({"message": "Success"}, status=HTTP_201_CREATED)
        else:
            return Response(serializer_class.errors, status=HTTP_400_BAD_REQUEST)

class AccountDeleteAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def delete(self, request, ):
        queryset = Account.objects.get(username=request.user.username)
        try:
            profile = Account.objects.get(uuid=queryset)
        except:
            pass
        queryset.delete()
        return Response(status=HTTP_200_OK)

@authentication_classes([])
@permission_classes([])
class AuthenticatedUser(APIView):
    def post(self, request, ):
        serializer_class = serializers.AuthenticateAccountSerializer(data=request.data)
        if serializer_class.is_valid():
            username = serializer_class.data.get('username')
            password = serializer_class.data.get('password')

            account = Account.objects.get(username=username)
            if account.check_password(raw_password=password):
                payload = {
                    'uuid': str(account.uuid),
                    'username': account.username,
                    'time': str(datetime.now(timezone.utc)),
                }
                access_token = jwt.encode(payload, settings.SECRET_KEY).decode('utf-8')
                try:
                    to_black_list = AccessToken.objects.get(user=account)
                    token_black_list = BlackList()
                    token_black_list.token = to_black_list.value
                    to_black_list.delete()
                    token_black_list.save()
                except:
                    pass

                to_access_token = AccessToken()
                to_access_token.user = account
                to_access_token.value = str(access_token)
                to_access_token.save()

                expires = datetime.now() + timedelta(seconds=300000)
                refresh_token = AccesssTokenOATH(
                    user=account,
                    expires=expires,
                    token=common.generate_token(),
                )

                refresh_token.save()
                payload2 = {'token': str(refresh_token)}
                refresh_token_str = jwt.encode(payload2, settings.SECRET_KEY).decode('utf-8')
                decode_token = jwt.decode(refresh_token_str, settings.SECRET_KEY)
                tokens = {
                    'access_token': access_token,
                    'refresh_token': refresh_token_str,
                }

                return Response(tokens, status=HTTP_201_CREATED)
            else:
                return Response({"message": "Authentication failed"}, status=HTTP_400_BAD_REQUEST)
 
class AuthenticationVerify(APIView):
    serializer_class = serializers.AuthenticateAccountSerializer
    permission_classes = (IsAuthenticated, )
    
    def get(self, request, format=None):
        return Response({'verify': True})

class AuthenticationMe(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, format=None):
        account = Account.objects.get(username=request.user.username)
        try:
            profile = Profile.objects.get(username=account).dictionary()
        except:
            profile = 'null'

        account_information = {
            'id': str(account.uuid),
            'username': account.username,
            'email': account.email,
            'timezone': account.timezone,
            'profile': profile
        }
        return Response(account_information, content_type='application/json')

class RefreshTokenAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request):
        serializer_class = serializers.RefreshTokenSerializer(data=request.data)
        if serializer_class.is_valid():
            token = serializer_class.data.get('refresh_token')
            decoded_token = jwt.decode(token, settings.SECRET_KEY)
            try:
                valid_token = AccesssTokenOATH.objects.get(token=decoded_token['token'])
                if datetime.now(timezone.utc) < valid_token.expires:
                    username = valid_token.user.username
                    account = Account.objects.get(username=username)
                    payload = {
                        'uuid': str(account.uuid),
                        'username': account.username,
                        'time': str(datetime.now(timezone.utc))
                    }
                    access_token = jwt.encode(payload, settings.SECRET_KEY).decode('utf-8')
                    return Response({"access_token": access_token}, status=HTTP_200_OK)
                else:
                    return Response(status=HTTP_400_BAD_REQUEST)
            except:
                return Response({"message": "Refresh token not found"}, status=HTTP_404_NOT_FOUND)
        else:
            return Response({"message": "Access token and refresh token do not match"}, status=HTTP_400_BAD_REQUEST)        

class RevokeAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request):
        serializers_class = serializers.RevokeSerializer(data=request.data)
        if serializers_class.is_valid():
            refresh_token = serializers_class.data.get('refresh_token')
            try:
                decoded_token = jwt.decode(refresh_token, settings.SECRET_KEY)['token']
                print(decoded_token)
            except:
                return Response(status=HTTP_400_BAD_REQUEST)
            try:
                to_delete_token = AccesssTokenOATH.objects.get(token=str(decoded_token))
                if to_delete_token.user.username != str(request.user.username):
                    return Response({"message": "Access token and refresh token do not match"}, status=HTTP_400_BAD_REQUEST)
                print(to_delete_token)
                to_delete_token.delete()
            except:
                return Response({"message": "Refresh token was not found"}, status=HTTP_404_NOT_FOUND)
        else:
            return Response(status=HTTP_400_BAD_REQUEST)
        return Response(status=HTTP_200_OK)

class ChangeEmailAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def patch(self, request):
        serializer_class = serializers.EmailSerializer(data=request.data)
        if serializer_class.is_valid():
            email = serializer_class.data.get('email')
            account = Account.objects.get(username=request.user.username)
            account.email = email
            account.save()
            return Response({"message": "Success"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid email"}, status=status.HTTP_400_BAD_REQUEST)

class SendConfirmedEmailAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request):
        account = Account.objects.get(username=request.user.username)
        to_email = account.email
        current_site = get_current_site(request)
        message = render_to_string('email_confirmed.html', {
            'user': account,
            'domain': current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(account.uuid)),
            'token': account_activation_token.make_token(account),
        })
        mail_confirmed = 'Active your account'
        to_email = to_email
        email_message = EmailMessage(mail_confirmed, message, to=[to_email])
        email_message.send()
        return Response({"message": "Success"}, status=HTTP_202_ACCEPTED)

def ConfirmEmailAPIView(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        account = Account.objects.get(uuid=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        account = None
    if account is not None and account_activation_token.check_token(account, token):
        account.is_active = True
        account.save()
        return HttpResponse(status=HTTP_200_OK)
    else:
        return HttpResponse({"message": "Token has been expired"}, status=HTTP_400_BAD_REQUEST)

class ChangePasswordAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def patch(self, request):
        serializer_class = serializers.ChangePasswordSerializer(data=request.data)
        if serializer_class.is_valid():
            current_password = serializer_class.data.get('current_password')
            password = serializer_class.data.get('password')
            confirmed_password = serializer_class.data.get('confirmed_password')
            account = Account.objects.get(username=request.user.username)
            if not account.check_password(raw_password=current_password):
                message = {"errors": {"current_password": "Incorect password"}}
                return Response(message, status=HTTP_400_BAD_REQUEST)
            else:
                account.password = make_password(password)
                account.save()
                try:
                    to_black_list = AccessToken.objects.get(username=account)
                    token_black_list = Blacklist()
                    token_black_list.token = to_black_list.value
                    to_black_list.delete()
                    token_black_list.save()
                except:
                    pass
            return Response({"message": "Success"}, status=HTTP_200_OK)
        else:
            return Response(serializer_class.errors, status=HTTP_400_BAD_REQUEST)

class ProfileAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def patch(self, request):
        serializer_class = serializers.ProfileSerializer(data=request.data)
        if serializer_class.is_valid():
            fullname = serializer_class.data.get('fullname')
            address = serializer_class.data.get('address')
            country = serializer_class.data.get('country')
            phone = serializer_class.data.get('phone')
            date_of_birth = serializer_class.data.get('date_of_birth')
        
            account = Account.objects.get(username=request.user.username)
            profiles = Profile.objects.all()

            if account in [profile.username for profile in profiles]:
                prof = profiles.get(username=account)
                if fullname != '':
                    prof.fullname = fullname
                if address != '':
                    prof.address = address
                if country != '':
                    prof.country = country
                if phone != '':
                    prof.phone = phone
                print(date_of_birth)
                if date_of_birth != '':
                    
                    prof.date_of_birth = date_of_birth
                prof.save()
                return Response(status=HTTP_200_OK)
            else:
                prof = Profile()
                prof.username = account
                prof.fullname = fullname
                prof.address = address
                prof.country = country
                prof.phone = phone
                prof.date_of_birth = date_of_birth
                prof.save()
                return Response(status=HTTP_200_OK)
        else:
            return Response(serializer_class.errors,status=HTTP_400_BAD_REQUEST)
