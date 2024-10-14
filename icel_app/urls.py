from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .views import contact_view
from .views import forgot_password, reset_password
# Ensure 'urlpatterns' is defined and has valid patterns
urlpatterns = [
    path("", views.login_view, name="index"),
    path("accounts/login/", views.login_view),
    path("accounts/logout/", views.logout_view),
    path("logout/", views.logout_view, name="logout"),
    path("signup/", views.signup_view, name="signup"),
    path("homepage/", views.homepage, name="homepage"),
    path("incident-form/", views.incident_form, name="incident_form"),
    path("pool-car-request/", views.pool_car_request, name="pool_car_request"),
    path("travel-notice/", views.travel_notice, name="travel_notice"),
    path("contact/", views.contact_view, name="contact"),
    path("requisitions/", views.requisitions, name="requisitions_form"),
    path('success/', views.success_view, name='success'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
]