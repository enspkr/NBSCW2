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

    async def receive_json(self, content):
        """
        İstemciden (JS) bir mesaj aldığımızda (örn: hamle yapıldı).
        """
        message_type = content.get('type')
        if not self.user.is_authenticated:
            await self.send_error("Giriş yapmalısınız.")
            return

        if message_type == 'make_move':
            row = content.get('row')
            col = content.get('col')

            game = await self.get_game(self.game_id)

            # --- OYUN GÜVENLİĞİ KONTROLLERİ ---
            if game.status != 'in_progress':
                await self.send_error("Oyun başlamadı veya bitti.")
                return

            if game.current_turn != self.user:
                await self.send_error("Sıra sizde değil.")
                return

            # (Buraya oyunun 'geçerli hamle mi?' kuralını eklemelisin)
            # Örneğin: hücre boş değilse ve sahibi siz değilseniz tıklayamazsınız
            cell = game.board_state[row][col]
            if cell and cell['owner'] != self.user.username:
                await self.send_error("Bu hücreye oynayamazsınız.")
                return

            # --- OYUN MANTIĞI ---
            # (Burada senin anlattığın 'patlama' mantığını uygulayacaksın)
            # Bu fonksiyon oyunun yeni state'ini, bir kazanan olup olmadığını
            # ve sıranın kime geçtiğini hesaplamalı.
            # Bu mantığı modelde bir metod olarak yazmak en temizidir.
            # new_state, new_turn_user, winner = game.apply_move(self.user, row, col)

            # --- Örnek Basit Hamle (Patlamasız) ---
            # BU KISMI KENDİ OYUN MANTIĞINLA DEĞİŞTİR
            game.board_state[row][col] = {'owner': self.user.username, 'count': cell['count'] + 1 if cell else 1}
            game.current_turn = game.player2 if self.user == game.player1 else game.player1
            # --- Örnek Bitti ---

            await self.save_game(game)

            # Herkese (oyuncular ve izleyiciler) yeni durumu yayınla
            await self.broadcast_game_state(game, message=f"{self.user.username} hamle yaptı.")

    # --- Yardımcı Metodlar ---

    async def broadcast_game_state(self, game, message=None):
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
            }
        )

    async def game_message(self, event):
        """
        'broadcast_game_state' tarafından grupta tetiklenen mesajı alır
        ve WebSocket üzerinden istemciye gönderir.
        """
        await self.send_json({
            'type': 'game_state',  # JS'in anlayacağı tip
            'state': event['state'],
            'turn': event['turn'],
            'p1': event['p1'],
            'p2': event['p2'],
            'status': event['status'],
            'winner': event['winner'],
            'message': event['message'],
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