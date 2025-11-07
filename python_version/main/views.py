import random

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib import messages
from django.db import models, transaction
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
    # 1. Başkalarının P2 bekleyen masaları (Bunlara 'Katıl'ınır)
    available_games = GameSession.objects.filter(
        status='waiting',
        player2__isnull=True
    ).exclude(player1=request.user)  # Kendi masalarımı hariç tut

    # 2. Benim aktif (bitmemiş) masalarım (Bunlara 'Git'ilir)
    my_games = GameSession.objects.filter(
        models.Q(player1=request.user) | models.Q(player2=request.user)
    ).exclude(status='finished').select_related('player1', 'player2')

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
    if GameSession.objects.filter(player1=request.user, status='waiting').exists():
        messages.warning(request, "Zaten bekleyen bir masanız var. Lütfen onu kapatın veya devam edin.")
        return redirect('game_lobby')

    # Başlangıç tahtasını hazırla (ilk 3'leri yerleştir)
    initial_board = default_board()

    game = GameSession.objects.create(
        player1=request.user,
        current_turn=None,
        board_state=initial_board
    )
    return redirect('game_room', game_id=game.game_id)


@login_required
@transaction.atomic
def join_game(request, game_id):
    """
    İsteği yapan kullanıcıyı P2 olarak ekler, kimin başlayacağını seçer
    ve P1'e WebSocket üzerinden haber verir.
    (GÜNCELLENDİ: Random başlama ve P1'e haber verme eklendi)
    """
    game = get_object_or_404(GameSession.objects.select_for_update(), game_id=game_id)

    # ... (standart kontrolleriniz: status != 'waiting', player2 is not None, vb.) ...
    if game.status != 'waiting' or game.player2 is not None or game.player1 == request.user:
        messages.error(request, "Bu masaya katılamazsınız.")
        return redirect('game_lobby')

    # 1. P2'yi ata
    game.player2 = request.user

    # 2. 50/50 Şansla kimin başlayacağını seç (İSTEK 3)
    starter = random.choice([game.player1, game.player2])
    game.current_turn = starter
    game.status = 'in_progress'
    game.save()

    # 3. P1'e HABER VER (İSTEK 1)
    # P1'in (ve şimdi P2'nin) bağlı olduğu gruba "oyun başladı" mesajı gönder
    channel_layer = get_channel_layer()
    game_group_name = f"game_{game_id}"

    async_to_sync(channel_layer.group_send)(
        game_group_name,
        {
            'type': 'game_message',  # Consumer'daki 'game_message' handler'ını tetikler
            'state': game.board_state,
            'turn': game.current_turn.username,
            'p1': game.player1.username,
            'p2': game.player2.username,
            'status': game.status,
            'winner': None,
            'message': f"{request.user.username} katıldı. Çark çevrildi ve {starter.username} başlıyor!",
            'exploded_cells': [],
            # JS'in çark animasyonunu tetiklemesi için özel event flag'i:
            'special_event': 'game_start_roll'
        }
    )

    return redirect('game_room', game_id=game.game_id)


@login_required
def game_room(request, game_id):
    """
    Asıl oyunun oynandığı WebSocket'in bağlanacağı HTML sayfasını sunar.
    (Otomatik katılma (auto-join) mantığı kaldırıldı)
    """
    try:
        # Oyunu al
        game = get_object_or_404(GameSession.objects.select_related('player1', 'player2', 'current_turn', 'winner'),
                                 game_id=game_id)

        # Oyuncu olmayan biri mi girmeye çalışıyor?
        is_player = (request.user == game.player1) or (request.user == game.player2)

        # Eğer P1 veya P2 değilseniz, izleyicisiniz.
        is_spectator = not is_player

        # --- OTOMATİK KATILMA BLOĞU (SORUNLU YER) KALDIRILDI ---
        # Artık 'join_game' linkine tıklamayan kimse P2 olamaz.
        # Buraya gelen ve P1/P2 olmayan herkes 'is_spectator = True' olur.
        # Bu, tam olarak istediğiniz "izleyici modu"dur.

        return render(request, 'game_room.html', {
            'game': game,
            'is_spectator': is_spectator,
            'game_id_json': str(game_id),
            'username_json': request.user.username
        })

    except GameSession.DoesNotExist:
        messages.error(request, "Oyun bulunamadı.")
        return redirect('game_lobby')


@login_required
def delete_game(request, game_id):
    """
    Player 1'in, beklemekte olan masasını silmesi (kapatması).
    (Bu kodunuz doğruydu, değişikliğe gerek yok)
    """
    game = get_object_or_404(GameSession, game_id=game_id)

    if game.player1 != request.user:
        messages.error(request, "Bu masayı siz oluşturmadınız.")
        return redirect('game_lobby')

    if game.status != 'waiting':
        messages.error(request, "Oyun başladıktan sonra masa silinemez.")
        return redirect('game_lobby')

    if game.player2 is not None:
        messages.error(request, "Masada 2. oyuncu varken silemezsiniz.")
        return redirect('game_lobby')

    game.delete()
    messages.success(request, "Masa başarıyla kapatıldı.")
    return redirect('game_lobby')