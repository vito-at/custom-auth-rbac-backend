from django.urls import get_resolver
from django.http import JsonResponse

def list_urls(request):
    urls = []
    for p in get_resolver().url_patterns:
        try:
            urls.append(str(p.pattern))
        except Exception:
            pass
    return JsonResponse({"urls": urls})
