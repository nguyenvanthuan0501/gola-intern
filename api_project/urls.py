from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url
from .views import (
    AccountCreateAPIView,
    AccountDeleteAPIView,
    AuthenticatedUser,
    AuthenticationVerify,
    AuthenticationMe,
    RefreshTokenAPIView,
    RevokeAPIView,
    ChangeEmailAPIView,
    SendConfirmedEmailAPIView,
    ConfirmEmailAPIView,
    ChangePasswordAPIView,
    ProfileAPIView
) 

urlpatterns = [
    path('auth/', AuthenticatedUser.as_view()),
    path('auth/verify/', AuthenticationVerify.as_view()),
    path('auth/me/', AuthenticationMe.as_view()),
    path('auth/refresh/', RefreshTokenAPIView.as_view()),
    path('auth/revoke/', RevokeAPIView.as_view()),
    path('accounts/', AccountCreateAPIView.as_view()),
    path('account/', AccountDeleteAPIView.as_view()),
    path('account/email/', ChangeEmailAPIView.as_view()),
    path('account/send-confirmed-email/', SendConfirmedEmailAPIView.as_view()),
    url(
        r'^account/confirm-email/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        ConfirmEmailAPIView, name='email_confirmed'),
    path('account/password', ChangePasswordAPIView.as_view()),
    path('profile/', ProfileAPIView.as_view()),
]
