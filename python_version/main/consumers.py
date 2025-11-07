from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.auth import get_user_model

from .models import GameSession

User = get_user_model()

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from urllib.parse import parse_qs
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import VoiceChannel


def get_valid_neighbors(row, col):
    # Olası komşu hamleleri (Yukarı, Aşağı, Sol, Sağ)
    # (n_row2, n_row, n_col2, n_col mantığınız)
    potential_moves = [
        (row - 1, col),  # Yukarı
        (row + 1, col),  # Aşağı
        (row, col - 1),  # Sol
        (row, col + 1)  # Sağ
    ]

    valid_neighbors = []

    for r, c in potential_moves:
        # Ana kontrolümüz:
        if 0 <= r < 5 and 0 <= c < 5:
            # Sınırların içindeyse listeye ekle
            valid_neighbors.append((r, c))
        else:
            # Sınır dışındaysa uyarı ver (isteğe bağlı)
            print(f"-> Geçersiz komşu atlandı: ({r}, {c})")

    return valid_neighbors
def find_critical_cells(board_state):
    """
    Verilen 5x5'lik board_state'i tarar.
    'count' değeri 4 olan hücrelerin (satır, sütun) koordinatlarını
    bir liste içinde döndürür.

    Args:
        board_state (list[list[dict|None]]): Oyun tahtasının mevcut durumu.

    Returns:
        list[tuple(int, int)]: 'count' == 4 olan hücrelerin (row, col) listesi.
    """

    # 5x5'lik bir tahta olduğunu varsayıyoruz
    ROWS = 5
    COLS = 5

    # 'count' değeri 4 olan hücrelerin koordinatlarını (r, c)
    # depolayacağımız liste.
    critical_cells = []

    for row in range(ROWS):
        for col in range(COLS):
            # O anki hücreyi al
            cell = board_state[row][col]

            # 1. Hücre dolu mu? (None değil mi?): 'if cell:'
            # 2. Doluysa 'count' değeri 4 mü?: 'cell['count'] == 4'
            if cell and cell.get('count') == 4:
                # Eğer iki koşul da doğruysa, koordinatları listeye ekle
                critical_cells.append((row, col))

    # Listeyi döndür
    return critical_cells
def bum(game, row, col, username):
    """
    (row, col) koordinatındaki hücreyi patlatır.
    1. Patlayan hücrenin sayısını 0 yapar.
    2. Komşu hücreleri bulur.
    3. Komşu hücrelerin sayısını 1 artırır (eğer boşsa 1 yapar).
    """

    # 1. Patlayan hücrenin kendisini sıfırla
    # (Bu hücrenin 'None' olmadığını ve 'count' == 4 olduğunu varsayıyoruz,
    # çünkü bu fonksiyonu 'while' döngüsü çağırdı)
    exploding_cell = game.board_state[row][col]
    exploding_cell['count'] = 0
    # Opsiyonel: Patlayan hücre sahipsiz kalabilir
    # exploding_cell['owner'] = None

    # 2. Geçerli komşuları al
    # (get_valid_neighbors fonksiyonunun tanımlı olduğunu varsayıyoruz)
    valids = get_valid_neighbors(row, col)

    # 3. Komşuları güncelle
    for r, c in valids:
        # Komşu hücrenin mevcut durumunu al
        current_cell = game.board_state[r][c]

        # --- ÖNCEKİ SORUNUN ÇÖZÜMÜ (None KONTROLÜ) ---
        if current_cell is None:
            # Hücre boşsa (NoneType), yeni hücre oluştur ve 1 yap
            game.board_state[r][c] = {
                'owner': username,
                'count': 1
            }
        else:
            # Hücre doluysa, 'count'u 1 artır ve sahibini güncelle
            current_cell['count'] += 1
            current_cell['owner'] = username

    # Bu fonksiyon 'game' objesini doğrudan değiştirdi,
    # bir şey döndürmesine gerek yok.
def check_for_winner(game, current_player_user):
    """
    Tüm patlamalar bittikten sonra, rakibin taşı kalmış mı diye kontrol eder.
    """
    # Rakibi belirle
    opponent = game.player2 if current_player_user == game.player1 else game.player1

    # Eğer rakip henüz yoksa (lobi) veya bir şekilde None ise kontrol etme
    if not opponent:
        return

    opponent_username = opponent.username
    opponent_pieces = 0

    # Tahtayı tara
    for r in range(5):
        for c in range(5):
            cell = game.board_state[r][c]
            # Rakibe ait bir hücre bulunduysa...
            if cell and cell.get('owner') == opponent_username:
                opponent_pieces += 1
                break  # Arama yapmayı bırak, rakibin taşı var.
        if opponent_pieces > 0:
            break  # Dış döngüden de çık

    # Döngüler bittiğinde rakibin hiç taşı bulunamadıysa...
    if opponent_pieces == 0:
        game.status = 'finished'
        game.winner = current_player_user

class VoiceChatConsumer(AsyncJsonWebsocketConsumer):

    # DB'den VoiceChannel objesini çeker
    @database_sync_to_async
    def get_channel_by_slug(self, slug):
        try:
            return VoiceChannel.objects.get(slug=slug)
        except VoiceChannel.DoesNotExist:
            return None

    async def connect(self):
        # 1. Kimlik Doğrulama Kontrolü
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        # 2. Oda adını/slug'ını al
        query_params = parse_qs(self.scope["query_string"].decode())
        self.channel_slug = query_params.get('channel_slug', [None])[0]

        if not self.channel_slug:
            await self.close()
            return

        # 3. Oda Var mı Kontrolü
        self.channel_object = await self.get_channel_by_slug(self.channel_slug)
        if not self.channel_object:
            await self.close()
            return

        self.channel_group_name = f'voice_{self.channel_slug}'
        self.user_id = str(self.scope["user"].id)

        # 4. Gruba (Odaya) katıl
        await self.channel_layer.group_add(
            self.channel_group_name,
            self.channel_name
        )

        await self.accept()

        # 5. Odaya katıldığını tüm gruba bildir
        await self.channel_layer.group_send(
            self.channel_group_name,
            {
                "type": "member.joined",
                "sender_id": self.user_id,
                "username": self.scope["user"].username,
            }
        )

    async def disconnect(self, close_code):
        if hasattr(self, 'channel_group_name') and self.channel_group_name and not self.scope["user"].is_anonymous:
            # 1. Gruptan (Oda) ayrıl
            await self.channel_layer.group_discard(
                self.channel_group_name,
                self.channel_name
            )
            # 2. Ayrıldığını gruba bildir
            await self.channel_layer.group_send(
                self.channel_group_name,
                {
                    "type": "member.left",
                    "sender_id": self.user_id,
                    "username": self.scope["user"].username,
                }
            )

        await super().disconnect(close_code)

    # --- Sinyalleşme ve Sohbet Mesajlarını İşleme ---

    async def receive_json(self, content, **kwargs):
        signal_type = content.get("signal_type")
        recipient_id = content.get("recipient_id")
        data = content.get("data")

        # 1. WebRTC Sinyalleşmesi (Offer/Answer/ICE)
        if signal_type in ['offer', 'answer', 'ice_candidate']:
            # Sinyali sadece ilgili alıcıya değil, gruba gönderiyoruz.
            # İstemci (JS) bu sinyalin kendisi için olup olmadığını kontrol edecek.
            await self.channel_layer.group_send(
                self.channel_group_name,
                {
                    "type": "webrtc.signal",
                    "sender_id": self.user_id,
                    "recipient_id": recipient_id,  # Kimin alması gerektiğini belirt
                    "signal_type": signal_type,
                    "data": data,
                }
            )

        # 2. Normal Sohbet Mesajı
        elif signal_type == 'chat_message':
            await self.channel_layer.group_send(
                self.channel_group_name,
                {
                    "type": "chat.message",
                    "sender_id": self.user_id,
                    "username": self.scope["user"].username,
                    "message": data,
                }
            )

        # 3. Durum Güncellemesi (Mute/Deafen)
        elif signal_type == 'status_update':
            await self.channel_layer.group_send(
                self.channel_group_name,
                {
                    "type": "member.status.update",
                    "sender_id": self.user_id,
                    "username": self.scope["user"].username,
                    "status": data  # {'muted': true, 'deafened': false}
                }
            )

    # --- Channel Layer'dan Gelen Olay İşleyicileri ---

    # Normal sohbet mesajlarını istemciye ilet
    async def chat_message(self, event):
        await self.send_json({
            "type": "chat_message",
            "sender_id": event["sender_id"],
            "username": event["username"],
            "message": event["message"],
        })

    # Yeni üye katılımını bildir
    async def member_joined(self, event):
        await self.send_json({
            "type": "system_notification",
            "event": "member_joined",
            "sender_id": event["sender_id"],
            "username": event["username"],
            "message": f"{event['username']} odaya katıldı."
        })

    # Üye ayrılışını bildir
    async def member_left(self, event):
        await self.send_json({
            "type": "system_notification",
            "event": "member_left",
            "sender_id": event["sender_id"],
            "username": event["username"],
            "message": f"{event['username']} odadan ayrıldı."
        })

    # WebRTC sinyallerini istemciye ilet
    async def webrtc_signal(self, event):
        await self.send_json({
            "type": "webrtc_signal",
            "sender_id": event["sender_id"],
            "recipient_id": event.get("recipient_id"),
            "signal_type": event["signal_type"],
            "data": event["data"],
        })

    # Durum güncellemesini gruba yayınla
    async def member_status_update(self, event):
        await self.send_json({
            "type": "member_status_update",
            "sender_id": event["sender_id"],
            "username": event["username"],
            "status": event["status"],
        })


class GameConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        """
        Bir kullanıcı odaya bağlandığında (oyuncu veya izleyici).
        """
        self.game_id = self.scope['url_route']['kwargs']['game_id']
        self.game_group_name = f'game_{self.game_id}'
        self.user = self.scope['user']  # <-- AuthMiddlewareStack sayesinde!

        # Gruba katıl (bu odadaki herkese yayın yapmak için)
        await self.channel_layer.group_add(
            self.game_group_name,
            self.channel_name
        )
        await self.accept()

        # Odaya yeni biri katıldığında (belki player2 budur)
        # Veritabanı işlemleri için sync_to_async kullan
        game = await self.get_game(self.game_id)

        # Eğer oyun bekliyorsa ve bağlanan kişi P1 değilse, onu P2 yap
        if game.status == 'waiting' and game.player1 != self.user and not game.player2:
            game.player2 = self.user
            game.board_state[4][4]['owner'] = self.user.username
            game.status = 'in_progress'
            await self.save_game(game)

            # Herkese (P1'e) yeni durumu ve P2'nin katıldığını bildir
            await self.broadcast_game_state(game, message=f"{self.user.username} oyuna katıldı.")
        else:
            # Sadece bağlanan kişiye mevcut oyun durumunu gönder
            await self.send_json({
                'type': 'game_state',
                'state': game.board_state,
                'turn': game.current_turn.username if game.current_turn else None,
                'p1': game.player1.username,
                'p2': game.player2.username if game.player2 else None,
            })

    async def disconnect(self, close_code):
        """Kullanıcı bağlantıyı kapattığında."""
        await self.channel_layer.group_discard(
            self.game_group_name,
            self.channel_name
        )

    async def receive_json(self, content,**kwargs):
        """
        İstemciden (JS) bir mesaj aldığımızda (örn: hamle yapıldı).
        (GÜNCELLENMİŞ VERSİYON - Animasyon ve Kazanan Kontrolü eklendi)
        """
        message_type = content.get('type')
        if not self.user.is_authenticated:
            await self.send_error("Giriş yapmalısınız.")
            return

        if message_type == 'make_move':
            row = content.get('row')
            col = content.get('col')

            game = await self.get_game(self.game_id)

            # --- GÜVENLİK KONTROLLERİ ---
            if game.status != 'in_progress':
                await self.send_error("Oyun başlamadı veya bitti.")
                return

            if game.current_turn != self.user:
                await self.send_error("Sıra sizde değil.")
                return

            # --- GEÇERLİ HAMLE KONTROLÜ ---
            cell = game.board_state[row][col]
            if cell and cell.get('owner') != self.user.username:
                await self.send_error("Bu hücre rakibinize ait.")
                return

            # --- İLK HAMLEYİ YAP ---
            current_cell = game.board_state[row][col]
            player_username = self.user.username

            if current_cell is None:
                game.board_state[row][col] = {'owner': player_username, 'count': 1}
            else:
                current_cell['count'] += 1
                current_cell['owner'] = player_username

            # --- ZİNCİRLEME REAKSİYON ---

            # Animasyon için hangi hücrelerin patladığını takip et
            exploded_cells_list = []

            cells_to_explode = find_critical_cells(game.board_state)

            while cells_to_explode:
                r, c = cells_to_explode.pop(0)

                # Bu hücrenin patladığını listeye ekle
                if (r, c) not in exploded_cells_list:
                    exploded_cells_list.append((r, c))

                bum(game, r, c, player_username)

                cells_to_explode = find_critical_cells(game.board_state)

            # --- KAZANAN KONTROLÜ ---
            # Patlamalar bittikten sonra, bu hamle ile oyunu bitirdi mi?
            check_for_winner(game, self.user)

            # --- OYUNU BİTİR ---
            if game.status != 'finished':
                # Oyun bitmediyse sırayı değiştir
                game.current_turn = game.player2 if self.user == game.player1 else game.player1

            await self.save_game(game)

            # --- YAYINLA (Animasyon verisiyle birlikte) ---
            await self.broadcast_game_state(
                game,
                message=f"{self.user.username} hamle yaptı.",
                exploded_cells=exploded_cells_list  # <-- JS'e animasyon için gönder
            )

    # --- Yardımcı Metodlar ---

    async def broadcast_game_state(self, game, message=None, exploded_cells=None):  # <-- 1. BURAYA EKLENDİ
        """
        Odada bulunan herkese (tüm kanallara) oyunun son durumunu gönderir.
        """
        await self.channel_layer.group_send(
            self.game_group_name,
            {
                'type': 'game_message',  # Bu, aşağıdakı 'game_message' fonksiyonunu tetikler
                'state': game.board_state,
                'turn': game.current_turn.username if game.current_turn else None,
                'p1': game.player1.username,
                'p2': game.player2.username if game.player2 else None,
                'status': game.status,
                'winner': game.winner.username if game.winner else None,
                'message': message,
                'exploded_cells': exploded_cells if exploded_cells is not None else []  # <-- 2. BURAYA EKLENDİ
            }
        )

    async def game_message(self, event):
        """
        Grup mesajını (event) alır ve istemciye (JS) WebSocket üzerinden gönderir.
        """
        # Veriyi istemciye (JS) JSON olarak gönder
        await self.send_json({
            'type': 'game_state',  # <-- JS'in anladığı 'type'
            'state': event['state'],
            'turn': event['turn'],
            'p1': event['p1'],
            'p2': event['p2'],
            'status': event['status'],
            'winner': event['winner'],
            'message': event['message'],
            'exploded_cells': event['exploded_cells']  # <-- 3. VERİ BURADAN JS'e GİDER
        })

    async def send_error(self, message):
        """Sadece bu kullanıcıya bir hata mesajı gönder."""
        await self.send_json({
            'type': 'error',
            'message': message
        })

    # --- Veritabanı (Sync) Metodları ---
    # Django ORM'i asenkron ortamda kullanmak için
    @sync_to_async
    def get_game(self, game_id):
        return GameSession.objects.select_related('player1', 'player2', 'current_turn', 'winner').get(game_id=game_id)

    @sync_to_async
    def save_game(self, game):
        game.save()