# from django.contrib import auth
from mandala import auth
# from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from mandala.auth.base_user import AbstractBaseUser, BaseUserManager
# from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import models
from django.db.models.manager import EmptyManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from mandala.auth.validators import UnicodeUsernameValidator


class AbstractBaseModel(models.Model):
    # 名称
    name = models.CharField(_('name'), max_length=255)
    # 代码
    code = models.CharField(_('code'), max_length=255)
    # 状态，开启或者禁用
    status = models.BooleanField(_('status'), default=True)
    # 排名（在页面中展示的时候按这个顺序来展示）
    rank = models.IntegerField(_('rank'), default=0)#默认可以设计成时间戳

    class Meta:
        abstract = True

class ModuleManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, code):
        return self.get(code=code)

class Module(AbstractBaseModel):
    # 代码
    code = models.CharField(_('code'), max_length=255, unique=True)
    # 图标
    icon = models.CharField(_('icon'), blank=True, null=True, max_length=255)
    # 链接
    url = models.CharField(_('url'), blank=True, null=True, max_length=255)
    # 父级模块
    parent = models.ForeignKey("self", related_name='children', verbose_name=_("parent"), blank=True, null=True, on_delete=models.CASCADE)
    # # 用户查看此模块需要拥有的权限
    # perms = models.ManyToManyField('Permission', verbose_name=_("permissions"), blank=True, null=True)

    class Meta:
        # app_label = app_label
        db_table = 'mandala_auth_module'
        verbose_name = _('module')
        verbose_name_plural = verbose_name
        # unique_together = (('code', 'parent'),)
        ordering = ('parent__rank', 'rank')

    # @property
    # def need_perms(self):
    #     perms = self.perms.values_list('module__code', 'code').order_by()
    #     return {"%s.%s" % (ct, name) for ct, name in perms}

    def _get_full_name(self):
        full_name = self.name
        if self.parent:
            full_name = self.parent._get_full_name() + " | " + full_name
        return full_name

    def __str__(self):
        return self._get_full_name()

    def natural_key(self):
        return (self.code,)


class PermissionManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, code, module_code):
        return self.get(
            code=code,
            module__code=module_code
        )


class Permission(AbstractBaseModel):
    # 属于哪个模块
    module = models.ForeignKey(Module, related_name="permissions", verbose_name=_("module"), blank=True, null=True, on_delete=models.CASCADE)

    objects = PermissionManager()

    class Meta:
        # app_label = app_label
        db_table = "mandala_auth_permission"
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')
        unique_together = (('code', 'module'),)
        ordering = ('module__parent__rank', 'module__rank', 'rank')

    def __str__(self):
        string = self.name
        if self.module:
            string = str(self.module) + " | " + string
        return string

    def natural_key(self):
        return (self.code, ) + self.module.natural_key()
    natural_key.dependencies = ['mandala.auth.Module']


class RoleManager(models.Manager):
    """
    The manager for the auth's Group model.
    """
    use_in_migrations = True

    def get_by_natural_key(self, name):
        return self.get(name=name)


class Role(AbstractBaseModel):

    name = models.CharField(_("name"), max_length=255, unique=True)
    permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('permissions'),
        related_name="roles",
        related_query_name="role",
        blank=True,
    )

    objects = RoleManager()

    class Meta:
        # app_label = app_label
        db_table = "mandala_auth_role"
        verbose_name = _('role')
        verbose_name_plural = _('roles')
        ordering = ('rank',)

    def __str__(self):
        return self.name

    def natural_key(self):
        return (self.name,)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        username = self.model.normalize_username(username)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, email, password, **extra_fields)


# A few helper functions for common logic between User and AnonymousUser.
def _user_get_all_permissions(user, obj):
    permissions = set()
    for backend in auth.get_backends():
        if hasattr(backend, "get_all_permissions"):
            permissions.update(backend.get_all_permissions(user, obj))
    return permissions

 
def _user_has_perm(user, perm, obj):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in auth.get_backends():
        if not hasattr(backend, 'has_perm'):
            continue
        try:
            if backend.has_perm(user, perm, obj):
                return True
        except PermissionDenied:
            return False
    return False


def _user_has_module_perms(user, app_label):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in auth.get_backends():
        if not hasattr(backend, 'has_module_perms'):
            continue
        try:
            if backend.has_module_perms(user, app_label):
                return True
        except PermissionDenied:
            return False
    return False

class PermissionsMixin(models.Model):
    """
    Add the fields and methods necessary to support the Role and Permission
    models using the ModelBackend.
    """
    is_superuser = models.BooleanField(
        _('superuser status'),
        default=False,
        help_text=_(
            'Designates that this user has all permissions without '
            'explicitly assigning them.'
        ),
    )
    roles = models.ManyToManyField(
        Role,
        verbose_name=_('roles'),
        blank=True,
        help_text=_(
            'The roles this user belongs to. A user will get all permissions '
            'granted to each of their roles.'
        ),
        related_name="users",
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="users",
        related_query_name="user",
    )

    class Meta:
        abstract = True

    def get_role_permissions(self, obj=None):
        """
        Return a list of permission strings that this user has through their
        roles. Query all available auth backends. If an object is passed in,
        return only permissions matching this object.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_role_permissions"):
                permissions.update(backend.get_role_permissions(self, obj))
        return permissions

    def get_group_permissions(self, obj=None):
        """
        Return a list of permission strings that this user has through their
        roles. Query all available auth backends. If an object is passed in,
        return only permissions matching this object.
        """
        return self.get_role_permissions(obj)

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Return True if the user has the specified permission. Query all
        available auth backends, but return immediately if any backend returns
        True. Thus, a user who has permission from a single auth backend is
        assumed to have permission in general. If an object is provided, check
        permissions for that object.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Return True if the user has each of the specified permissions. If
        object is passed, check if the user has all required perms for it.
        """
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label):
        """
        Return True if the user has any permissions in the given app label.
        Use similar logic as has_perm(), above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)

# class PermissionsMixin(OldPermissionsMixin):
#     groups = None
#     roles = models.ManyToManyField(
#         Role,
#         verbose_name=_('roles'),
#         blank=True,
#         help_text=_(
#             'The roles this user belongs to. A user will get all permissions '
#             'granted to each of their roles.'
#         ),
#         related_name="user_set",
#         related_query_name="user",
#     )

#     class Meta:
#         abstract = True

#     def get_role_permissions(self, obj=None):
#         """
#         Return a list of permission strings that this user has through their
#         roles. Query all available auth backends. If an object is passed in,
#         return only permissions matching this object.
#         """
#         permissions = set()
#         for backend in auth.get_backends():
#             if hasattr(backend, "get_role_permissions"):
#                 permissions.update(backend.get_role_permissions(self, obj))
#         return permissions

#     def get_group_permissions(self, obj=None):
#         """
#         Return a list of permission strings that this user has through their
#         roles. Query all available auth backends. If an object is passed in,
#         return only permissions matching this object.
#         """
#         return self.get_role_permissions(obj)

class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username and password are required. Other fields are optional.
    """
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    # first_name = models.CharField(_('first name'), max_length=30, blank=True)
    # last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        # full_name = '%s %s' % (self.first_name, self.last_name)
        # return full_name.strip()
        return self.username

    def get_short_name(self):
        """Return the short name for the user."""
        # return self.first_name
        return self.username

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)


# class User(AbstractUser):
#     """
#     Users within the Django authentication system are represented by this
#     model.

#     Username and password are required. Other fields are optional.
#     """
#     class Meta(AbstractUser.Meta):
#         swappable = 'AUTH_USER_MODEL'
        

# class UserModel(User):
#     nickname
#     avatar
#     department
#     position

#     status


class User(AbstractUser):
    """
    Users within the Django authentication system are represented by this
    model.

    Username and password are required. Other fields are optional.
    """
    nickname = models.CharField(_('nickname'), max_length=255)

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
        # app_label = app_label
        db_table = "mandala_auth_user"
        verbose_name = _('user')
        verbose_name_plural = _('users')


class AnonymousUser:
    id = None
    pk = None
    username = ''
    is_staff = False
    is_active = False
    is_superuser = False
    _roles = EmptyManager(Role)
    _user_permissions = EmptyManager(Permission)

    def __str__(self):
        return 'AnonymousUser'

    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __hash__(self):
        return 1  # instances always return the same hash value

    def __int__(self):
        raise TypeError('Cannot cast AnonymousUser to int. Are you trying to use it in place of User?')

    def save(self):
        raise NotImplementedError("Django doesn't provide a DB representation for AnonymousUser.")

    def delete(self):
        raise NotImplementedError("Django doesn't provide a DB representation for AnonymousUser.")

    def set_password(self, raw_password):
        raise NotImplementedError("Django doesn't provide a DB representation for AnonymousUser.")

    def check_password(self, raw_password):
        raise NotImplementedError("Django doesn't provide a DB representation for AnonymousUser.")

    @property
    def roles(self):
        return self._roles

    @property
    def user_permissions(self):
        return self._user_permissions

    def get_role_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj=obj)

    def has_perm(self, perm, obj=None):
        return _user_has_perm(self, perm, obj=obj)

    def has_perms(self, perm_list, obj=None):
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, module):
        return _user_has_module_perms(self, module)

    @property
    def is_anonymous(self):
        return True

    @property
    def is_authenticated(self):
        return False

    def get_username(self):
        return self.username
