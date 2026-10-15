"""
Django settings for SENTINEL-X project.
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SENTINELX_SECRET_KEY')
DEBUG = os.environ.get('DEBUG', 'False').strip().lower() in {'1', 'true', 'yes'}
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = 'local-development-only-change-me'
    else:
        raise RuntimeError('SENTINELX_SECRET_KEY must be set when DEBUG is disabled')

ALLOWED_HOSTS = [
    host.strip() for host in os.environ.get(
        'ALLOWED_HOSTS', 'localhost,127.0.0.1'
    ).split(',') if host.strip()
]

# Cloud deployments default to demo-safe mode. Real wiping/erasure operations
# must only run in a separately isolated, explicitly configured local lab.
SENTINELX_CLOUD_DEMO = os.environ.get(
    'SENTINELX_CLOUD_DEMO', 'true'
).strip().lower() in {'1', 'true', 'yes'}

# Custom User Model
AUTH_USER_MODEL = 'authentication.User'

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',

    # SENTINEL-X Local Apps
    'apps.authentication.apps.AuthenticationConfig',
    'apps.dashboard.apps.DashboardConfig',
    'apps.devices.apps.DevicesConfig',
    'apps.sanitization.apps.SanitizationConfig',
    'apps.file_erasure.apps.FileErasureConfig',
    'apps.recovery.apps.RecoveryConfig',
    'apps.forensic.apps.ForensicConfig',
    'apps.verification.apps.VerificationConfig',
    'apps.audit.apps.AuditConfig',
    'apps.reports.apps.ReportsConfig',
    'apps.ledger.apps.LedgerConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
}

LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/auth/login/'
