# Generated by Django 5.1.4 on 2025-04-13 16:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_profile_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='reset_token',
            field=models.TextField(blank=True, null=True),
        ),
    ]
