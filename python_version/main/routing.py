from django.urls import re_path
from . import consumers # Consumer'ınızı bu dosyaya import edin

websocket_urlpatterns = [
    # İstemci (Front-end) bu adrese bağlanır: ws://domain/ws/voice/?channel_slug=oda-adi
    re_path(r'ws/voice/$', consumers.VoiceChatConsumer.as_asgi()),
    re_path(r'ws/game/(?P<game_id>[0-9a-f-]+)/$', consumers.GameConsumer.as_asgi()),
]