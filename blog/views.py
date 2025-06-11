from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from .models import Blog
from .serializers import BlogSerializer, UserSerializer, BlogSerializerWithoutImage, BlogWithEmailSerializer
from .permissions import IsAuthorOrReadOnly
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import BlogSerializerWithoutImage
from django.db import models
from django.shortcuts import get_object_or_404
from rest_framework import pagination


# User registration view
class RegisterUser(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        if not username or not email or not password:
            return Response({'error': 'Please provide username, email and password'}, status=400)
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=400)
        user = User.objects.create_user(username=username, email=email, password=password)
        return Response({'message': 'User created successfully'})

# User login view
class LoginUser(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response({'success': False, 'error': 'Please provide email and password'}, status=400)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'success': False, 'error': 'Invalid credentials'}, status=400)

        user = authenticate(request, username=user.username, password=password)

        if user:
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            return Response({
                'success': True,
                'message': 'Login successful',
                'token': access_token,
                'refresh': str(refresh),  # Optional
            }, status=200)
        else:
            return Response({'success': False, 'error': 'Invalid credentials'}, status=400)

# User logout view
class LogoutUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        logout(request)
        return Response({'message': 'Logout successful'})

# Blog list and create view
class BlogListCreateView(generics.ListCreateAPIView):
    queryset = Blog.objects.all().order_by('-created_at')
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "success": True,
            "posts": serializer.data
        })
        
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


# Blog detail, update, delete view
class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAuthorOrReadOnly]


class BlogsByEmailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, email):
        """Get all blogs by email (only if it's the authenticated user's email)"""
        # Security check: users can only access their own blogs
        if request.user.email != email:
            return Response({
                'success': False,
                'error': 'You can only access your own blogs'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = get_object_or_404(User, email=email)
            blogs = Blog.objects.filter(author=user).order_by('-created_at')
            serializer = BlogWithEmailSerializer(blogs, many=True)
            return Response({
                'success': True,
                'blogs': serializer.data,
                'count': blogs.count(),
                'user': user.username
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Get current user info
class CurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get current authenticated user information"""
        user = request.user
        serializer = UserSerializer(user)
        return Response({
            'success': True,
            'user': serializer.data
        }, status=status.HTTP_200_OK)
        
class UserBlogsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all blogs by the authenticated user"""
        user = request.user
        blogs = Blog.objects.filter(author=user).order_by('-created_at')
        serializer = BlogSerializer(blogs, many=True)
        return Response({
            'success': True,
            'blogs': serializer.data,
            'count': blogs.count()
        }, status=status.HTTP_200_OK)
