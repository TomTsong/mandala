# Generated by Django 2.2.4 on 2020-07-07 05:35

import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import mandala.auth.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Module',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, verbose_name='name')),
                ('status', models.BooleanField(default=True, verbose_name='status')),
                ('rank', models.IntegerField(default=0, verbose_name='rank')),
                ('code', models.CharField(max_length=255, unique=True, verbose_name='code')),
                ('icon', models.CharField(blank=True, max_length=255, null=True, verbose_name='icon')),
                ('url', models.CharField(blank=True, max_length=255, null=True, verbose_name='url')),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='auth.Module', verbose_name='父模块')),
            ],
            options={
                'verbose_name': 'module',
                'verbose_name_plural': 'module',
                'db_table': 'mandala_auth_module',
                'ordering': ('parent__rank', 'rank'),
            },
        ),
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, verbose_name='name')),
                ('code', models.CharField(max_length=255, verbose_name='code')),
                ('status', models.BooleanField(default=True, verbose_name='status')),
                ('rank', models.IntegerField(default=0, verbose_name='rank')),
                ('module', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='auth.Module', verbose_name='模块')),
            ],
            options={
                'verbose_name': 'permission',
                'verbose_name_plural': 'permissions',
                'db_table': 'mandala_auth_permission',
                'ordering': ('module__parent__rank', 'module__rank', 'rank'),
                'unique_together': {('code', 'module')},
            },
            managers=[
                ('objects', mandala.auth.models.PermissionManager()),
            ],
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=255, verbose_name='code')),
                ('status', models.BooleanField(default=True, verbose_name='status')),
                ('rank', models.IntegerField(default=0, verbose_name='rank')),
                ('name', models.CharField(max_length=255, unique=True, verbose_name='name')),
                ('permissions', models.ManyToManyField(blank=True, to='auth.Permission', verbose_name='permissions')),
            ],
            options={
                'verbose_name': 'role',
                'verbose_name_plural': 'roles',
                'db_table': 'mandala_auth_role',
                'ordering': ('rank',),
            },
            managers=[
                ('objects', mandala.auth.models.RoleManager()),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('nickname', models.CharField(max_length=255, verbose_name='nickname')),
                ('roles', models.ManyToManyField(blank=True, help_text='The roles this user belongs to. A user will get all permissions granted to each of their roles.', related_name='user_set', related_query_name='user', to='auth.Role', verbose_name='roles')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'db_table': 'mandala_auth_user',
                'abstract': False,
                'swappable': 'AUTH_USER_MODEL',
            },
            managers=[
                ('objects', mandala.auth.models.UserManager()),
            ],
        ),
    ]
