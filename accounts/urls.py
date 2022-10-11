from django.urls import path
from . import views

urlpatterns = [
    path("registerUser/", views.registerUser, name="registerUser"),
    path("registerVendor/", views.registerVendor, name="registerVendor"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("my-account/", views.my_account, name="my_account"),
    path("customer-dashboard/", views.customer_dashboard, name="customer_dashboard"),
    path("vendor-dashboard/", views.vendor_dashboard, name="vendor_dashboard"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path(
        "reset-password-validate/<uidb64>/<token>/",
        views.reset_password_validate,
        name="reset_password_validate",
    ),
    path("reset-password/", views.reset_password, name="reset_password"),
]
