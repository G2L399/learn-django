from django.urls import path
from .views import BookList, BookDetail, Login, LoginView, ProtectedView
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

#calling Class-Based Views (CBV)
urlpatterns = [
    path('api/books/', BookList.as_view(), name='book_list_api'),
    path('api/books/<int:pk>/', BookDetail.as_view(), name='book_detail_api'),
    path('authors/', views.AuthorList, name='author-list'),
    path('authors/<int:pk>/', views.AuthorDetail, name='author-detail'),
    path('Login/', Login.as_view(), name='Login'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/protected/', ProtectedView.as_view(), name='protected'),
    path('Person/', views.PersonView.as_view(), name='Get_Person'),
]