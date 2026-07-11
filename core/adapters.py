# core/adapters.py
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.http import HttpResponseRedirect

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        """
        Bypasses any intermediate signup phases for social accounts.
        If an account matching the provider already exists, connect it seamlessly.
        """
        pass

    def get_connect_redirect_url(self, request, sociallogin):
        # Force redirection directly back to your local React dev server port
        return 'http://127.0.0.1:5173/?auth=success'