from django.urls import path

from . import views
from .views import ForgotPasswordView

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
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot_password"),
]
