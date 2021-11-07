from rest_framework import serializers
from .models import MyUser
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6,
                                     write_only=True)

    class Meta:
        model = MyUser
        fields = ['email', 'password']  # username

    def validate(self, attrs):
        email = attrs.get('email', '')
        # username = attrs.get('username', '')
        if not email:
            raise serializers.ValidationError(
                self.default_error_messages)

        return attrs

    def create(self, validated_data):
        return MyUser.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6,
                                     write_only=True)
    email = serializers.EmailField()
    # username = serializers.CharField(max_length=255, min_length=3)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = MyUser.objects.get(email=obj['email'])  # username
        return {
            'refresh': user.tokens()['refresh'],  # username
            'access': user.tokens()['access']
        }

    class Meta:
        model = MyUser
        fields = ['password', 'email', 'tokens']  # username

    def validate(self, attrs):
        email = attrs.get('email', '')  # username
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)  # username
        if not email:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not MyUser.is_active == False:
            raise AuthenticationFailed('Account disabled, contact admin')
        return {
            'email': user.email,
            # 'username': user.username,
            'tokens': user.tokens
        }


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
