# Generated by Django 3.2.19 on 2024-03-22 18:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('commandcenter', '0023_generalconfiguration_hostname'),
    ]

    operations = [
        migrations.AddField(
            model_name='extrafieldspec',
            name='description',
            field=models.TextField(blank=True),
        ),
    ]