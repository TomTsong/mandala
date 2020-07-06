from django.shortcuts import render
from django.http import HttpResponse
from mandala.auth import get_user_model
from mandala.auth.models import Permission, Role, Module

# Create your views here.

UserModel = get_user_model()

def user_list(request):
    return HttpResponse(UserModel.objects.all())

def module_list(request):
    return HttpResponse(Module.objects.all())

def role_list(request):
    return HttpResponse(Role.objects.all())

def perm_list(request):
    return HttpResponse(Permission.objects.all())
