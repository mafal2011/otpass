# Generated by Django 4.2.6 on 2023-10-18 04:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otpass', '0002_alter_userpwd_pwd'),
    ]

    operations = [
        migrations.CreateModel(
            name='GlobalVar',
            fields=[
                ('var_nm', models.CharField(max_length=30, primary_key=True, serialize=False)),
                ('var_val', models.TextField()),
            ],
        ),
    ]