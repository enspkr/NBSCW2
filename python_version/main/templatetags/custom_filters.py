from django import template

register = template.Library()

@register.filter(name='add_class')
def add_class(value, arg):
    """Bootstrap sınıfını forma ekler."""
    return value.as_widget(attrs={'class': arg})