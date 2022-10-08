def detect_user_role(user):
    if user.role == 1:
        redirect_url = "vendor_dashboard"
    elif user.role == 2:
        redirect_url = "customer_dashboard"
    elif user.role == None and user.is_superadmin:
        redirect_url = "/admin"
    return redirect_url
