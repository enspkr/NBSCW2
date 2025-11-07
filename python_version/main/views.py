from django.contrib import messages
from django.db import models
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from .models import VoiceChannel, GameSession, default_board


@login_required
def index(request):
    channels = VoiceChannel.objects.all().order_by('name')

    context = {
        'channels': channels,
        'title': 'Sesli Sohbet Odaları',
    }
    return render(request, 'index.html', context)


@login_required
def voice_channel_view(request, slug):
    """Tek bir sesli sohbet odası ve chat arayüzü."""

    channel = get_object_or_404(VoiceChannel, slug=slug)

    context = {
        'channel': channel,
        'title': f'#{channel.name} Odası',
        # Kullanıcının oda slug'ını JavaScript'e aktarmak için
        'channel_slug': slug,
    }
    return render(request, 'oda.html', context)

@login_required
def settings_view(request):
    """Kullanıcının mikrofon/hoparlör seçimi yapacağı ayarlar sayfası."""
    return render(request, 'settings.html', {'title': 'Ayarlar'})


@login_required
def game_lobby(request):
    """
    Açık masaları listeler ve yeni masa oluşturma butonu sunar.
    """
    available_games = GameSession.objects.filter(status='waiting')
    my_games = GameSession.objects.filter(models.Q(player1=request.user) | models.Q(player2=request.user)).exclude(
        status='finished')

    return render(request, 'lobby.html', {
        'available_games': available_games,
        'my_games': my_games
    })


@login_required
def create_game(request):
    """
    Yeni bir oyun masası oluşturur ve oyuncuyu odaya yönlendirir.
    """
    # Oyuncunun zaten bekleyen bir masası var mı diye kontrol et
    if not GameSession.objects.filter(player1=request.user, status='waiting').exists():
        # Başlangıç tahtasını hazırla (ilk 3'leri yerleştir)
        initial_board = default_board()
        initial_board[0][0] = {'owner': request.user.username, 'count': 3}
        initial_board[4][4] = {'owner': None, 'count': 3}  # 2. oyuncu gelince güncellenecek

        game = GameSession.objects.create(
            player1=request.user,
            current_turn=request.user,  # İlk hamle player1'de
            board_state=initial_board
        )
        return redirect('game_room', game_id=game.game_id)
    return redirect('game_lobby')


@login_required
def game_room(request, game_id):
    """
    Asıl oyunun oynandığı WebSocket'in bağlanacağı HTML sayfasını sunar.
    """
    try:
        game = GameSession.objects.get(game_id=game_id)

        # Oyuncu olmayan biri mi girmeye çalışıyor?
        # İzleyici olarak izin vereceğiz, ancak JS'nin bilmesi lazım.
        is_player = (request.user == game.player1) or (request.user == game.player2)
        is_spectator = not is_player

        # Eğer bekleyen bir oyunsa ve giren kişi player1 değilse, onu player2 yap
        if game.status == 'waiting' and game.player1 != request.user and not game.player2:
            game.player2 = request.user
            # İkinci oyuncu için de başlangıç taşı koy
            game.board_state[4][4]['owner'] = request.user.username
            game.status = 'in_progress'
            game.save()
            # NOT: Bu değişiklik WebSocket üzerinden diğer oyuncuya bildirilmeli!
            # (Bunu Consumer'da yapacağız)

        return render(request, 'game_room.html', {
            'game': game,
            'is_spectator': is_spectator,
            'game_id_json': str(game_id),  # JS'e göndermek için
            'username_json': request.user.username
        })

    except GameSession.DoesNotExist:
        return redirect('game_lobby')