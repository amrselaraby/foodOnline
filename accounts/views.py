from django.shortcuts import render, redirect
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages
from vendor.forms import VendorForm

# Create your views here.
def registerUser(request):
    if request.method == "POST":

        form = UserForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data["password"]
            user = form.save(commit=False)
            user.set_password(password)
            user.role = User.CUSTOMER
            user.save()
            messages.success(request, "Your account has been registered successfully")
            return redirect("registerUser")
        else:
            print("Invalid form")
            print(form.errors)
    else:
        form = UserForm()
    context = {"form": form}
    return render(request, "accounts/registerUser.html", context=context)


def registerVendor(request):
    if request.method == "POST":
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
