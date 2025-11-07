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
    initial_board[0][0] = {'owner': request.user.username, 'count': 3}
    initial_board[4][4] = {'owner': None, 'count': 3}  # P2 katılınca güncellenecek

    game = GameSession.objects.create(
        player1=request.user,
        current_turn=request.user,
        board_state=initial_board
    )
    return redirect('game_room', game_id=game.game_id)


@login_required
@transaction.atomic  # Race condition (iki kişinin aynı anda katılması) önlemi
def join_game(request, game_id):
    """
    İsteği yapan kullanıcıyı, Player 2 olarak bekleyen bir oyuna ekler.
    (Tek katılma yöntemi budur)
    """
    game = get_object_or_404(GameSession.objects.select_for_update(), game_id=game_id)

    if game.status != 'waiting':
        messages.error(request, "Bu oyun çoktan başlamış.")
        return redirect('game_lobby')

    if game.player2 is not None:
        messages.error(request, "Bu masa çoktan dolmuş.")
        return redirect('game_lobby')

    if game.player1 == request.user:
        messages.error(request, "Kendi masanıza katılamazsınız.")
        return redirect('game_lobby')

    # --- 2. OYUNCU BAŞARIYLA KATILDI ---
    game.player2 = request.user
    game.status = 'in_progress'
    # (Opsiyonel) Sıra hala P1'de kalabilir veya P2'ye geçebilir, P1 kalsın:
    game.current_turn = game.player1

    # Başlangıç taşını P2'ye ata (create_game'de None idi)
    game.board_state[4][4]['owner'] = request.user.username

    game.save()

    # (Burada lobiye "bu masa doldu" diye bir WS mesajı atılabilir)

    # Katılan oyuncuyu odaya yönlendir
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