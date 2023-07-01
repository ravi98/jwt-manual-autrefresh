from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from datetime import datetime, timedelta
from .serializers import UserSerializer, AuthTokenSerializer

import jwt
import requests
import json

@api_view(['GET'])
def routes(request):
    return Response(
        [
            'api/token/',
            'api/token/refresh',
        ]
    )


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['name'] = user.username
        token['email'] = user.email
        
        # response=Response()
        # response.set_cookie(key='access', value)

        return token


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class=MyTokenObtainPairSerializer


class Register(APIView):
    
    def post(self, request):
        print(f"request data: {request.data}")
        serializer=UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        print(f"serializer data: {serializer.data}")
        return Response(serializer.data)


class LoginView(TokenObtainPairView):
    # serializer_class=AuthTokenSerializer
    
    def post(self, request):
        # username=request.data['username']
        # password=request.data['password']
        ser=AuthTokenSerializer(data=request.data)
        if ser.is_valid():
            data=ser.validated_data
            print(data)
            response=Response()
            response.set_cookie(key='access_token', value=data['access'], httponly=True)
            response.set_cookie(key='refresh_token', value=data['refresh'], httponly=True)
            response.data={
                'jwt': data['access'],
                'success': True
            }
            
            return response
        return Response({})



# class LoginView(APIView):
#     serializer_class=AuthTokenSerializer
    
#     def post(self, request):
#         username=request.data['username']
#         password=request.data['password']
        
#         user=AuthTokenSerializer(data=request.data).is_valid(raise_exception=True)
#         print(user)
#         # if not user:
#         #     raise AuthenticationFailed('User not found')
#         # if not user.check_password(password):
#         #     raise AuthenticationFailed('Incorret password')
#         if user:
#             user=get_user_model().objects.filter(username=username).first()
#         # serializer=UserSerializer(user)
#         # return Response(serializer.data)
        
#         payload={
#             'user_id': user.id,
#             'name': user.username,
#             'email': user.email,
#             'iat': datetime.utcnow(),
#             'exp': datetime.utcnow()+timedelta(minutes=60),
#         }
        
#         token=jwt.encode(payload, 'secret', algorithm='HS256')
#         response=Response()
#         response.set_cookie(key='jwt', value=token, httponly=True)
#         response.data={
#             'jwt': token,
#             'success': True
#         }
        
#         return response


class UserView(APIView):
    def get(self, request):
        token=request.COOKIES.get('access_token')
        response=Response()
        print(request.user)
        if not token:
            return redirect('user-login')
        try:
            user_id=jwt.decode(token, 'secret', algorithms=['HS256'])['user_id']
        except jwt.ExpiredSignatureError:
            print(f'expired sig')
            token=request.COOKIES.get('refresh_token')
            data={
                'refresh': token,
            }
            refresh_response=requests.post(url=f"http://localhost:8000{reverse('token_refresh')}", json=data)
            token_data=json.loads(refresh_response.content)
            print(token_data)
            response.set_cookie(key='access_token', value=token_data['access'], httponly=True)
            response.set_cookie(key='refresh_token', value=token_data['refresh'], httponly=True)
            user_id=jwt.decode(token_data['access'], 'secret', algorithms=['HS256'])['user_id']
        except Exception as e:
            return print(e)
        user=get_user_model().objects.get(id=user_id)
        serializer=UserSerializer(user)
        response.data=serializer.data
        
        return response

class LogOutView(APIView):
    def post(self, request):
        response=Response()
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        response.data={
            'message':'success'
        }
        return response