# Generated by Django 5.1.1 on 2024-11-21 21:20

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_alter_emailverification_expiry_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='expiry_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 21, 21, 35, 29, 109311, tzinfo=datetime.timezone.utc)),
        ),
    ]
