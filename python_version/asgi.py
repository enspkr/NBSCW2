import os
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack # <-- 1. AuthMiddleware'ı import edin

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'python_version.settings')

# Django'nun ayarlarını ve HTTP işleyicisini yükle
django_asgi_app = get_asgi_application()
import main.routing # <-- 2. Uygulamanızın routing dosyasını import edin

application = ProtocolTypeRouter({
    "http": django_asgi_app, # Normal HTTP istekleri (Sayfa yükleme, API'ler)
    
    # WebSocket bağlantıları için:
    "websocket": AuthMiddlewareStack( # <-- 3. WebSocket'i kimlik doğrulama katmanından geçir
        URLRouter(
            main.routing.websocket_urlpatterns
        )
    ),
})