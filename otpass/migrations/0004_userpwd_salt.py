# Generated by Django 4.2.6 on 2023-10-18 04:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otpass', '0003_globalvar'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpwd',
            name='salt',
            field=models.BinaryField(default=b'\x05\xd0\xb2\x04fU"\x06P\x8b\xad\x10=\xb0\xf9\x02'),
            preserve_default=False,
        ),
    ]