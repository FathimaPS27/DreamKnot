from django import template

register = template.Library()

@register.filter
def sentiment_class(score):
    """Convert sentiment score to CSS class."""
    try:
        score = float(score)
        if score >= 0.05:
            return 'positive'
        elif score <= -0.05:
            return 'negative'
        else:
            return 'neutral'
    except (ValueError, TypeError):
        return 'neutral'

@register.filter
def sentiment_label(score):
    """Convert sentiment score to readable label."""
    try:
        score = float(score)
        if score >= 0.05:
            return 'Positive'
        elif score <= -0.05:
            return 'Negative'
        else:
            return 'Neutral'
    except (ValueError, TypeError):
        return 'Neutral'


@register.filter
def get_item(dictionary, key):
    """
    Template filter to get an item from a dictionary using a key
    Usage: {{ dictionary|get_item:key }}
    """
    return dictionary.get(str(key))