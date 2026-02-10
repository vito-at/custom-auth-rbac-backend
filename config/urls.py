from django.urls import path
from core import views
from core.ui_views import (
    UiIndexView,
    UiRegisterView,
    UiLoginView,
    UiMeView,
)

urlpatterns = [
    
    path("ui/", UiIndexView.as_view()),
    path("ui/register", UiRegisterView.as_view()),
    path("ui/login", UiLoginView.as_view()),
    path("ui/me", UiMeView.as_view()),

   
    # AUTH API
    path("api/auth/register", views.RegisterView.as_view()),
    path("api/auth/login", views.LoginView.as_view()),
    path("api/auth/logout", views.LogoutView.as_view()),

   
    # USER
    path("api/users/me", views.MeView.as_view()),

  
    # MOCK BUSINESS OBJECTS
    path("api/mock/projects", views.MockProjectsView.as_view()),
    path("api/mock/reports", views.MockReportsView.as_view()),
]
