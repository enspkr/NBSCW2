from django.urls import path
from . import views
from django.contrib.auth import views as auth_views # auth_views'i import edin

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('oda/<slug:slug>/', views.voice_channel_view, name='odasayfasi'),
    path('settings/', views.settings_view, name='settings'),

    path('game/', views.game_lobby, name='game_lobby'),

    # örn: http://site.com/game/create/
    path('create/', views.create_game, name='create_game'),

    # örn: http://site.com/game/room/UUID.../
    path('room/<uuid:game_id>/', views.game_room, name='game_room'),
    path('join/<uuid:game_id>/', views.join_game, name='join_game'),
    path('delete/<uuid:game_id>/', views.delete_game, name='delete_game'),
]