from django.shortcuts import render
from django.views import View

class UiIndexView(View):
    def get(self, request):
        return render(request, "ui/index.html")

class UiRegisterView(View):
    def get(self, request):
        return render(request, "ui/register.html")

class UiLoginView(View):
    def get(self, request):
        return render(request, "ui/login.html")

class UiMeView(View):
    def get(self, request):
        return render(request, "ui/me.html")
