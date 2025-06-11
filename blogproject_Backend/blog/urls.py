from django.urls import path
from .views import RegisterUser, LoginUser, LogoutUser, BlogListCreateView, BlogDetailView, BlogsByEmailView , UserBlogsView ,BlogsByEmailView,CurrentUserView

urlpatterns = [
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', LoginUser.as_view(), name='login'),
    path('logout/', LogoutUser.as_view(), name='logout'),
    path('blogs/', BlogListCreateView.as_view(), name='blog-list-create'),
    path('blogs/<int:pk>/', BlogDetailView.as_view(), name='blog-detail'),
    
    path('my-blogs/', UserBlogsView.as_view(), name='user-blogs'),
    path('blogs/by-email/<str:email>/', BlogsByEmailView.as_view(), name='blogs-by-email'),
    
    path('me/', CurrentUserView.as_view(), name='current-user'),
]
