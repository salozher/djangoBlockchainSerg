# S.Melchakov
# Blockchain (final assignment)
# December 2020
# https://github.com/salozher/djangoBlockchainSerg


from __future__ import unicode_literals
from django.contrib.auth.models import User, BaseUserManager, AbstractBaseUser
from django.db import models


class MyUserManager(BaseUserManager):
    def create_user(self, username, email, password):
        if not username:
            raise ValueError('Users must have a user name')
        if not email:
            raise ValueError('User must have a valid email address')
        user = self.model(
            username=username,
            email=self.normalize_email(email),
        )
        user.is_admin = False
        # user.is_authenticated = False
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        user = self.create_user(username, email, password=password)
        user.is_admin = True
        # user.is_authenticated = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    username = models.CharField(verbose_name='username', max_length=100, unique=True, )
    email = models.EmailField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    # is_authenticated = models.BooleanField(default=False)
    objects = MyUserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class Block(models.Model):
    index = models.IntegerField(verbose_name='index', )
    timestamp = models.CharField(verbose_name='timestamp', max_length=100, )
    transactions = models.TextField(verbose_name='transactions', )
    proof = models.IntegerField(verbose_name='proof', )
    previous_hash = models.CharField(verbose_name='previous_hash', max_length=100, )

    def __str__(self):
        return str(self.index)

    def delete(self, *args, **kwargs):
        super(Block, self).delete(*args, **kwargs)


class TransactionsBuffer(models.Model):
    unique_id = models.CharField(verbose_name='unique_id', max_length=100, unique=True, )
    sender = models.CharField(verbose_name='sender', max_length=100, )
    recipient = models.CharField(verbose_name='recipient', max_length=100, )
    amount = models.IntegerField(verbose_name='amount', )

    def __str__(self):
        return self.unique_id

    def delete(self, *args, **kwargs):
        super(TransactionsBuffer, self).delete(*args, **kwargs)


class Node(models.Model):
    url = models.CharField(verbose_name='url', max_length=100, unique=True, )

    def __str__(self):
        return self.url

    def delete(self, *args, **kwargs):
        super(Node, self).delete(*args, **kwargs)


# a class that i plan to use for my next (SD4) project
class Picture(models.Model):
    image = models.BinaryField(blank=True)

    def __str__(self):
        return 'this is picture'

    def delete(self, *args, **kwargs):
        super(Picture, self).delete(*args, **kwargs)
