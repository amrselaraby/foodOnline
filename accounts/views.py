from email.errors import MessageError
from typing import Type
from django.shortcuts import render, redirect

from accounts.utils import (
    detect_user_role,
    send_verification_email,
)
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages, auth
from vendor.forms import VendorForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

# Restrict the vendor from accessing the customer dashboard
def check_role_vendor(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied


# Restrict the customer from accessing the vendor dashboard
def check_role_customer(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied


def registerUser(request):
    if request.user.is_authenticated:
        messages.warning(request, "you are already registered")
        return redirect("dashboard")
    elif request.method == "POST":

        form = UserForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data["password"]
            user = form.save(commit=False)
            user.set_password(password)
            user.role = User.CUSTOMER
            user.save()
            # Send verification email to the user
            mail_subject = "Please activate your account"
            email_template = "accounts/emails/account_verification_email.html"
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(request, "Your account has been registered successfully")
            return redirect("login")
        else:
            print("Invalid form")
            print(form.errors)
    else:
        form = UserForm()
    context = {"form": form}
    return render(request, "accounts/registerUser.html", context=context)


def registerVendor(request):
    if request.user.is_authenticated:
        messages.warning(request, "you are already registered")
        return redirect("dashboard")
    elif request.method == "POST":
        # store the data and create the user
        form = UserForm(request.POST)
        vendor_form = VendorForm(request.POST, request.FILES)
        if form.is_valid() and vendor_form.is_valid():
            password = form.cleaned_data["password"]
            user = form.save(commit=False)
            user.set_password(password)
            user.role = User.VENDOR
            user.save()
            vendor = vendor_form.save(commit=False)
            vendor.user = user
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            # Send activation email
            mail_subject = "Please activate your account"
            email_template = "accounts/emails/account_verification_email.html"
            send_verification_email(request, user, mail_subject, email_template)

            messages.success(
                request,
                "Your account has been registered successfully! Please wait for the approval.",
            )
            return redirect("registerVendor")
        else:
            print(form.errors)
            print(vendor_form.errors)
    else:
        form = UserForm()
        vendor_form = VendorForm()
    context = {"form": form, "vendor_form": vendor_form}
    return render(request, "accounts/registerVendor.html", context)


def login(request):
    if request.user.is_authenticated:
        messages.warning(request, "you are already logged in")
        return redirect("my_account")

    elif request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]
        user = auth.authenticate(email=email, password=password)
        if user:
            auth.login(request, user)
            messages.success(request, "You are now logged in")
            return redirect("my_account")
        else:
            messages.error(request, "Invalid Credentials")
            return redirect("login")
    return render(request, "accounts/login.html")


def logout(request):
    auth.logout(request)
    messages.info(request, "اراك قريبا")
    return redirect("login")


@login_required(login_url="login")
def my_account(request):
    user = request.user
    redirect_url = detect_user_role(user)
    return redirect(redirect_url)


@login_required(login_url="login")
@user_passes_test(check_role_customer)
def customer_dashboard(request):
    return render(request, "accounts/customer_dashboard.html")


@login_required(login_url="login")
@user_passes_test(check_role_vendor)
def vendor_dashboard(request):
    return render(request, "accounts/vendor_dashboard.html")


def activate(request, uidb64, token):
    # Activating the user by setting is_active to True
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Congratulation you account is now active")
        return redirect("my_account")
    else:
        messages.error(request, "Invalid activation link")
        return redirect("my_account")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST["email"]

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            # Send the password email
            mail_subject = "Reset Your Password"
            email_template = "accounts/emails/reset_password_email.html"
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(
                request, "Password reset link has been sent to your email address"
            )
            return redirect("login")
        else:
            messages.error(request, "Account does not exist")
            return redirect("forgot_password")
    return render(request, "accounts/forgot_password.html")


def reset_password_validate(request, uidb64, token):
    # validate the user by decoding the uidb and the token
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session["uid"] = uid
        messages.info(request, "Please reset your password.")
        return redirect("reset_password")
    else:
        messages.error(request, "This link has been expired")
        return redirect("my_account")


def reset_password(request):
    if request.method == "POST":
        password = request.POST["password"]
        confirm_password = request.POST["confirm_password"]

        if password == confirm_password:
            pk = request.session["uid"]
            user = User.objects.get(pk=pk)
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request, "Password reset successfully")
            return redirect("login")
        else:
            messages.error(request, "Passwords does not match")
            return redirect("reset_password")
    return render(request, "accounts/emails/reset_password.html")
