# Generated by Django 5.1.1 on 2024-09-09 19:48

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_customuser_is_active_emailverification'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='expiry_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 9, 9, 20, 3, 45, 99928, tzinfo=datetime.timezone.utc)),
        ),
    ]
