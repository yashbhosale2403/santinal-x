from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from apps.authentication.models import User


def login_view(request):
    if request.user.is_authenticated:
        return redirect('/')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {user.username} ({user.get_role_display()})!")
            return redirect('/')
        messages.error(request, "Invalid username or password credentials.")

    return render(request, 'authentication/login.html')


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('/')

    public_roles = [
        (User.Role.INVESTIGATOR, 'Forensic Investigator'),
        (User.Role.OPERATOR, 'Sanitization Operator'),
        (User.Role.VIEWER, 'Auditor / Viewer'),
    ]

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')
        requested_role = request.POST.get('role', User.Role.VIEWER)
        # Administrator is never assignable through public self-registration.
        allowed_roles = {User.Role.INVESTIGATOR, User.Role.OPERATOR, User.Role.VIEWER}
        role = requested_role if requested_role in allowed_roles else User.Role.VIEWER
        department = request.POST.get('department', '').strip()
        badge_id = request.POST.get('badge_id', '').strip()

        errors = []
        if not username:
            errors.append("Username is required.")
        if User.objects.filter(username=username).exists():
            errors.append("This username is already taken.")
        if email and User.objects.filter(email=email).exists():
            errors.append("This email address is already registered.")
        if password != password_confirm:
            errors.append("Passwords do not match.")

        if not errors:
            try:
                validate_password(password)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if errors:
            for error in errors:
                messages.error(request, error)
            return render(request, 'authentication/signup.html', {
                'form_data': {
                    'username': username,
                    'email': email,
                    'role': role,
                    'department': department,
                    'badge_id': badge_id,
                },
                'roles': public_roles,
            })

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            role=role,
            department=department,
            badge_id=badge_id,
        )
        login(request, user)
        messages.success(request, f"Welcome to SENTINEL-X, {user.username}! Your account has been created.")
        return redirect('/')

    return render(request, 'authentication/signup.html', {'roles': public_roles})


def logout_view(request):
    logout(request)
    messages.info(request, "Logged out successfully.")
    return redirect('/auth/login/')
