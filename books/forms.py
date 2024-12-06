from django import forms
from .models import Book, Person
from . import models

class BookForm(forms.ModelForm):
    class Meta:
        model = Book
        fields = ['title', 'author']
class PersonForm(forms.ModelForm):    
    class Meta:
        model = Person
        fields = ['name', 'username','password']
      
    def save(self, commit=True):
        print(self)
        """
        Override the save method to hash the password before saving the user.
        """
        person = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            person.set_password(password)
        if commit:
            person.save()
        return person