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
        # Generate tokens
        refresh = RefreshToken.for_user(person)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'name': person.name,
            'username': person.username,
            'role': person.role,
        }, status=status.HTTP_200_OK)
        
        
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        return Response({'message': 'This is a protected view!'})
    
class PersonView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        form = PersonForm(request.data)
        if form.is_valid():
            person = form.save()
            serializer = PersonSerializer(person)
            print(person)
            return Response({'message': 'Person created successfully','data': serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    def get(self, request):
        persons = Person.objects.all()
        serializer = PersonSerializer(persons, many=True)
        return Response(serializer.data)