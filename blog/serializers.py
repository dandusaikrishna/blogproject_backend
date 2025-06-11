from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Blog

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class BlogSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)

    class Meta:
        model = Blog
        fields = ['id','title', 'description' ,'content','image','read_time','comments', 'created_at', 'updated_at','author']
        

class BlogSerializerWithoutImage(serializers.ModelSerializer):
    author = serializers.StringRelatedField()

    class Meta:
        model = Blog
        exclude = ['image']  # Exclude image field


class BlogWithEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='author.email', read_only=True)

    class Meta:
        model = Blog
        fields = ['id', 'title', 'description', 'content', 'read_time', 'comments', 'created_at', 'updated_at', 'email']
