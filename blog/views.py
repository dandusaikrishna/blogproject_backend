from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from .models import Blog
from .serializers import BlogSerializer, UserSerializer
from .permissions import IsAuthorOrReadOnly
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import BlogSerializerWithoutImage
from django.db import models
from django.shortcuts import get_object_or_404
from rest_framework import pagination

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from .models import Blog
from .serializers import BlogSerializer, UserSerializer, BlogSerializerWithoutImage, BlogWithEmailSerializer
from .permissions import IsAuthorOrReadOnly
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404



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
    
class BlogListCreateView(generics.ListCreateAPIView):
    queryset = Blog.objects.all().order_by('-created_at')
    serializer_class = BlogSerializer
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        GET requests (list) - Allow any user (public access)
        POST requests (create) - Require authentication
        """
        if self.request.method == 'GET':
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [permissions.IsAuthenticated]
        
        return [permission() for permission in permission_classes]
    
    def list(self, request, *args, **kwargs):
        """List all blogs - accessible to everyone"""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "success": True,
            "posts": serializer.data
        })
        
    def create(self, request, *args, **kwargs):
        """Create a new blog - requires authentication"""
        if not request.user.is_authenticated:
            return Response({
                'success': False,
                'error': 'Authentication required to create a blog'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response({
                'success': True,
                'message': 'Blog created successfully',
                'blog': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Blog detail, update, delete view
class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        GET requests (retrieve) - Allow any user (public access)
        PUT/PATCH/DELETE requests - Require user to be author
        """
        if self.request.method == 'GET':
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [IsAuthorOrReadOnly]
        
        return [permission() for permission in permission_classes]
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single blog - accessible to everyone"""
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({
                'success': True,
                'blog': serializer.data
            })
        except Blog.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Blog not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    def update(self, request, *args, **kwargs):
        """Update a blog - requires authentication and ownership"""
        if not request.user.is_authenticated:
            return Response({
                'success': False,
                'error': 'Authentication required to update a blog'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        instance = self.get_object()
        if instance.author != request.user:
            return Response({
                'success': False,
                'error': 'You can only edit your own blogs'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'success': True,
                'message': 'Blog updated successfully',
                'blog': serializer.data
            })
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        """Delete a blog - requires authentication and ownership"""
        if not request.user.is_authenticated:
            return Response({
                'success': False,
                'error': 'Authentication required to delete a blog'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        instance = self.get_object()
        if instance.author != request.user:
            return Response({
                'success': False,
                'error': 'You can only delete your own blogs'
            }, status=status.HTTP_403_FORBIDDEN)
        
        instance.delete()
        return Response({
            'success': True,
            'message': 'Blog deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)
        

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
