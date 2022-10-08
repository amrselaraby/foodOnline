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
]
