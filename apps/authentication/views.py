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
        u = request.POST.get('username')
        p = request.POST.get('password')
        
        user = authenticate(request, username=u, password=p)
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {user.username} ({user.get_role_display()})!")
            return redirect('/')
        else:
            messages.error(request, "Invalid username or password credentials.")

    return render(request, 'authentication/login.html')


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('/')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')
        role = request.POST.get('role', User.Role.VIEWER)
        department = request.POST.get('department', '').strip()
        badge_id = request.POST.get('badge_id', '').strip()

        # Validation
        errors = []
        if not username:
            errors.append("Username is required.")
        if User.objects.filter(username=username).exists():
            errors.append("This username is already taken.")
        if email and User.objects.filter(email=email).exists():
            errors.append("This email address is already registered.")
        if password != password_confirm:
            errors.append("Passwords do not match.")
        if role not in [choice[0] for choice in User.Role.choices]:
            errors.append("Invalid role selected.")

        # Django password strength validation
        if not errors:
            try:
                validate_password(password)
            except ValidationError as e:
                errors.extend(e.messages)

        if errors:
            for err in errors:
                messages.error(request, err)
            return render(request, 'authentication/signup.html', {
                'form_data': {
                    'username': username,
                    'email': email,
                    'role': role,
                    'department': department,
                    'badge_id': badge_id,
                },
                'roles': User.Role.choices,
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            role=role,
            department=department,
            badge_id=badge_id,
        )
        login(request, user)
        messages.success(request, f"Welcome to SENTINEL-X, {user.username}! Your account has been created as {user.get_role_display()}.")
        return redirect('/')

    return render(request, 'authentication/signup.html', {
        'roles': User.Role.choices,
    })


def logout_view(request):
    logout(request)
    messages.info(request, "Logged out successfully.")
    return redirect('/auth/login/')
