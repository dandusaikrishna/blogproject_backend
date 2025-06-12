# CLEAN IMPORTS - Remove duplicates
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Blog
from .serializers import (
    BlogSerializer, 
    UserSerializer, 
    BlogSerializerWithoutImage, 
    BlogWithEmailSerializer
)
from .permissions import IsAuthorOrReadOnly


class RegisterUser(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')
            
            if not username or not email or not password:
                return Response({
                    'success': False,
                    'error': 'Please provide username, email and password'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if User.objects.filter(username=username).exists():
                return Response({
                    'success': False,
                    'error': 'Username already exists'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if User.objects.filter(email=email).exists():
                return Response({
                    'success': False,
                    'error': 'Email already exists'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            user = User.objects.create_user(
                username=username, 
                email=email, 
                password=password
            )
            return Response({
                'success': True,
                'message': 'User created successfully'
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginUser(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            
            if not email or not password:
                return Response({
                    'success': False, 
                    'error': 'Please provide email and password'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({
                    'success': False, 
                    'error': 'Invalid credentials'
                }, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(request, username=user.username, password=password)

            if user:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                
                return Response({
                    'success': True,
                    'message': 'Login successful',
                    'token': access_token,
                    'refresh': str(refresh),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False, 
                    'error': 'Invalid credentials'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            logout(request)
            return Response({
                'success': True,
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BlogListCreateView(generics.ListCreateAPIView):
    queryset = Blog.objects.all().order_by('-created_at')
    serializer_class = BlogSerializer
    
    def get_permissions(self):
        """
        Public access for GET (list blogs)
        Authentication required for POST (create blog)
        """
        if self.request.method == 'GET':
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [permissions.IsAuthenticated]
        
        return [permission() for permission in permission_classes]
    
    def list(self, request, *args, **kwargs):
        """List all blogs - PUBLIC ACCESS"""
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "posts": serializer.data,
                "count": queryset.count()
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def create(self, request, *args, **kwargs):
        """Create blog - AUTHENTICATED USERS ONLY"""
        try:
            if not request.user.is_authenticated:
                return Response({
                    'success': False,
                    'error': 'Authentication required to create a blog'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save(author=request.user)
                return Response({
                    "success": True,
                    "message": "Blog created successfully",
                    "blog": serializer.data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "success": False,
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    
    def get_permissions(self):
        """
        Public access for GET (read single blog)
        Authentication + ownership required for PUT/PATCH/DELETE
        """
        if self.request.method == 'GET':
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [IsAuthorOrReadOnly]
        
        return [permission() for permission in permission_classes]
    
    def retrieve(self, request, *args, **kwargs):
        """Get single blog - PUBLIC ACCESS"""
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({
                "success": True,
                "blog": serializer.data
            }, status=status.HTTP_200_OK)
        except Blog.DoesNotExist:
            return Response({
                "success": False,
                "error": "Blog not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def update(self, request, *args, **kwargs):
        """Update blog - AUTHOR ONLY"""
        try:
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
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def destroy(self, request, *args, **kwargs):
        """Delete blog - AUTHOR ONLY"""
        try:
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
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BlogsByEmailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, email):
        """Get user's own blogs by email - AUTHENTICATED USERS ONLY"""
        try:
            if request.user.email != email:
                return Response({
                    'success': False,
                    'error': 'You can only access your own blogs'
                }, status=status.HTTP_403_FORBIDDEN)
            
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


class CurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get current user info - AUTHENTICATED USERS ONLY"""
        try:
            user = request.user
            serializer = UserSerializer(user)
            return Response({
                'success': True,
                'user': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserBlogsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get current user's blogs - AUTHENTICATED USERS ONLY"""
        try:
            user = request.user
            blogs = Blog.objects.filter(author=user).order_by('-created_at')
            serializer = BlogSerializer(blogs, many=True)
            return Response({
                'success': True,
                'blogs': serializer.data,
                'count': blogs.count()
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
