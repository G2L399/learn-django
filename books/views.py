from django.utils import timezone
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Book,Author, Person
from .serializers import BookSerializer,AuthorSerializer,PersonSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from .forms import PersonForm
from django.utils.timezone import now
from django.contrib.auth import authenticate,login
import pyotp
from django.core.mail import send_mail
from django.http import JsonResponse
from django.conf import settings
from django.utils.timezone import make_aware
from .utils import add_user_to_redis, get_user_from_redis, delete_user_from_redis


# Class-Based Views (CBV)
class BookList(APIView):
    def get(self, request):
        books = Book.objects.all()
        serializer = BookSerializer(books, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BookSerializer(data=request.data)
        print("indian",serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BookDetail(APIView):
    def get(self, request, pk):
        book = Book.objects.get(pk=pk)
        serializer = BookSerializer(book)
        return Response(serializer.data)

    def put(self, request, pk):
        book = Book.objects.get(pk=pk)
        serializer = BookSerializer(book, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        book = Book.objects.get(pk=pk)
        book.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
#Function_based view    
@api_view(['GET', 'POST'])
def AuthorList(request):
    print("hello")
    if (request.method == 'GET'):
        print("hello")
        authors = Author.objects.all()
        serializer = AuthorSerializer(authors, many=True)
        return Response(serializer.data)

    elif (request.method == 'POST'):
        serializer = AuthorSerializer(data=request.data)
        print(request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'PUT', 'DELETE'])
def AuthorDetail(request,pk):
    try:
        author = Author.objects.get(pk=pk)
        print()
    except Book.DoesNotExist:
        return Response({'error': 'Book not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if(request.method == 'GET'):
        author = Author.objects.get(pk=pk)
        serializer = AuthorSerializer(author)
        return Response(serializer.data)

    elif request.method == 'PUT':
        author = Author.objects.get(pk=pk)
        serializer = AuthorSerializer(author, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        author = Author.objects.get(pk=pk)
        author.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class Login(APIView):
    def get(self, request):
        books = Person.objects.all()
        serializer = PersonSerializer(books, many=True)
        return Response(serializer.data)
    def post(self, request):
        print(request)
        serializer = PersonSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate the user
        person = authenticate(request, username=username, password=password)
        if person is None:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Update `last_login` automatically (done by `login`)
        login(request, person)  # Optionally use this if you're using session-based authentication
        
        #otp
        otp_secret = pyotp.random_base32()
        # print(base64.b32encode(settings.SECRET_KEY))
        totp = pyotp.TOTP(otp_secret, digits=6)
        otp = totp.now()
        send_mail(
                'Your OTP Code',
                f'Your OTP code is: {otp}',
                settings.EMAIL_HOST_USER,
                ["bagassatwi@gmail.com"],  # Assuming the `Person` model has an `email` field
                fail_silently=False,
            )
        request.session['otp'] = otp
        request.session['otp_timestamp'] = now().isoformat()
        print(type(timezone.now()))
        # Generate tokens
        refresh = RefreshToken.for_user(person)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'name': person.name,
            'username': person.username,
            'role': person.role,
        }, status=status.HTTP_200_OK)
class OTPView(APIView):
    def post(self, request):
        otp_from_request = request.data.get('otp')
        otp_from_session = request.session.get('otp')
        otp_timestamp = request.session.get('otp_timestamp')
        if (otp_timestamp is not None):
            otp_timestamp = datetime.fromisoformat(otp_timestamp)  # No need for `make_aware`
        else:
            return Response({"error": "OTP doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
        if (timezone.now() - otp_timestamp > timedelta(minutes=5)):
            return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)
        elif(otp_from_session is None):
            return Response({"error": "OTP doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
        else:

            print((timezone.now() - otp_timestamp).seconds > timedelta(minutes=5).total_seconds())
            if otp_from_request == otp_from_session:
                request.session.pop('otp', None)  # Removes 'otp' if it exists, does nothing otherwise
                request.session.pop('otp_timestamp', None)  # Removes 'otp_timestamp' if it exists
                return Response({"message": "OTP Verified! You are logged in."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        return Response({'message': 'This is a protected view!'})
    
class PersonView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        form = PersonForm(request.data)
        print("PlaceHolder ",request.data['username'])
        if form.is_valid():
            person = form.save(commit=False)
            print(person.password)
            otp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(otp_secret, digits=6)
            otp = totp.now()
            redis_key = f'username:{request.data['username']}'
            user_data = {
                'name': person.name,
                'username': person.username,
                'password': person.password,
                'otp': otp
            }
            add_user_to_redis(redis_key, user_data, timeout=300)
            send_mail(
                'Your OTP Code',
                f'Your OTP code is: {otp}',
                settings.EMAIL_HOST_USER,
                ["bagassatwi@gmail.com"],  # Assuming the `Person` model has an `email` field
                fail_silently=False
            )
            return Response({'message': 'OTP sent to your email!'}, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    def get(self, request):
        persons = Person.objects.all()
        serializer = PersonSerializer(persons, many=True)
        return Response(serializer.data)
class VerifyOTPSignUp(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        otp = request.data.get('otp')
        redis_key = f'username:{username}'
        user_data = get_user_from_redis(redis_key)
        print(user_data)
        if user_data is None:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        elif(user_data['otp'] == otp and user_data is not None):
            serializer = PersonSerializer(data=user_data)
            if serializer.is_valid():
                serializer.save()
                delete_user_from_redis(redis_key)
                return Response({'message':"OTP verified",'data':user_data},status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)