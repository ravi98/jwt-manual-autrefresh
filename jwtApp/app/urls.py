from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from django.urls import path
from .views import routes, MyTokenObtainPairView, Register, LoginView, UserView, LogOutView


urlpatterns = [
    path('', routes),
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', Register.as_view(), name='user-register'),
    path('login/', LoginView.as_view(), name='user-login'),
    path('user/', UserView.as_view(), name='get-user'),
    path('logout/', LogOutView.as_view(), name='user-logout'),
]

