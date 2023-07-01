from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=get_user_model()
        fields=['id', 'username', 'email', 'password']
        extra_kwargs = {'password':{
			'write_only':True, 'min_length':5
		}}
    
    def create(self, validated_data):
        password=validated_data.pop('password', None)
        user_instance=self.Meta.model(**validated_data)
        if password is not None:
            user_instance.set_password(password)
        user_instance.save()
        
        return user_instance

class AuthTokenSerializer(TokenObtainPairSerializer):
    """Serializer for the user auth token"""
    username=serializers.CharField()
    password=serializers.CharField(
        style={'input_type':'password'},
        trim_whitespace=False, # django trims whitespace from charfields by default.
    )
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['name'] = user.username
        token['email'] = user.email
        token['user_id'] =user.id
        
        # response=Response()
        # response.set_cookie(key='access', value)

        return token
    
    def validate(self, attrs):
        """validate and authenticate the users."""
        data = super().validate(attrs)
        username=attrs.get('username')
        password=attrs.get('password')
        user=authenticate(
            request=self.context.get('request'),
            username=username,
            password=password,
        )
        if not user:
            msg=('Unable to authenticate the user with provided credentials')
            raise serializers.ValidationError(msg, code='authorization')
        
        attrs['user']=user
        attrs['access']=data["access"]
        attrs["refresh"]=data["refresh"]
        # print(attrs)
        return attrs
    
            
        