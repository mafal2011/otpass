from django.contrib import admin
from django.urls import path, include # include를 새로 import
from otpass import views

urlpatterns = [
    path('', view=views.test_func),
    path('pubkey/', view=views.req_otpass_pubkey),
    path('otpass_mail/', view=views.req_otpass_mail),
]