from django.urls import path, re_path

# from . import views
from mandala.auth import views

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('password_change/', views.PasswordChangeView.as_view(), name='password_change'),
    path('password_change/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),

    path('password_reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),

    # re_path(r'^user/list$', views.user_list, name="user_list"),
    # re_path(r'^role/list$', views.role_list, name="role_list"),
    # re_path(r'^perm/list$', views.perm_list, name="perm_list"),
    # re_path(r'^module/list$', views.module_list, name="module_list"),
]

