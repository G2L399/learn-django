# Generated by Django 5.1.3 on 2024-12-05 09:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('books', '0002_person_email_person_groups_person_is_active_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='person',
            name='email',
        ),
        migrations.RemoveField(
            model_name='person',
            name='groups',
        ),
        migrations.RemoveField(
            model_name='person',
            name='is_active',
        ),
        migrations.RemoveField(
            model_name='person',
            name='is_staff',
        ),
        migrations.RemoveField(
            model_name='person',
            name='is_superuser',
        ),
        migrations.RemoveField(
            model_name='person',
            name='last_login',
        ),
        migrations.RemoveField(
            model_name='person',
            name='user_permissions',
        ),
        migrations.AlterField(
            model_name='person',
            name='username',
            field=models.CharField(max_length=100),
        ),
    ]
