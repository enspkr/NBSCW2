from django.contrib import admin
from .models import VoiceChannel, ChannelMember
from django.utils.text import slugify  # Slug oluşturmak için


# -----------------
# 1. VoiceChannel Admin Sınıfı
# -----------------

@admin.register(VoiceChannel)
class VoiceChannelAdmin(admin.ModelAdmin):
    # Admin listesinde gösterilecek alanlar
    list_display = ('name', 'slug', 'is_private')

    # Listede filtreleme yapabileceğimiz alanlar
    list_filter = ('is_private',)

    # Admin arama çubuğunda arama yapabileceğimiz alanlar
    search_fields = ('name', 'slug')

    # ChannelMember'ları bu kanalı düzenlerken gösterebiliriz (isteğe bağlı)
    # inlines = [ChannelMemberInline]

    # Otomatik slug oluşturma (Admin arayüzünde çok kullanışlı)
    prepopulated_fields = {'slug': ('name',)}

    # Yalnızca adminlerin görebileceği/düzenleyebileceği alanlar
    # fields = ('name', 'slug', 'is_private') # Tüm alanları göstermek isterseniz

    # Kullanıcı kaydederken çalışacak metod
    def save_model(self, request, obj, form, change):
        # Eğer slug alanı boşsa veya otomatik doldurulmamışsa, name alanından otomatik slug oluştururuz.
        if not obj.slug:
            obj.slug = slugify(obj.name)
        super().save_model(request, obj, form, change)


# -----------------
# 2. ChannelMember Admin Sınıfı (İsteğe Bağlı)
# -----------------

@admin.register(ChannelMember)
class ChannelMemberAdmin(admin.ModelAdmin):
    # ChannelMember'ları listelerken gösterilecek alanlar
    list_display = ('user', 'channel', 'is_online', 'joined_at')

    # Kolay filtreleme
    list_filter = ('channel', 'is_online')

    # Kolay arama
    search_fields = ('user__username', 'channel__name')