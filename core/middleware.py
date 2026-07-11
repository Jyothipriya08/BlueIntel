# core/middleware.py
from django.shortcuts import redirect
from django.urls import reverse

class DashboardAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Define routes that require an authenticated session
        if request.path.startswith('/dashboard/'):
            if not request.user.is_authenticated:
                return redirect(reverse('login'))
        
        response = self.get_response(request)
        return response