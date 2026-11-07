"""API views (synthetic fixture)."""
from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse

from django_site.api.models import Note


def note_list(request):
    notes = Note.objects.filter(owner=request.user)
    return JsonResponse({"notes": [n.title for n in notes]})


def note_search(request):
    term = request.GET.get("q", "")
    rows = Note.objects.extra(where=["title LIKE %s"], params=[f"%{term}%"])
    return JsonResponse({"results": [r.title for r in rows]})


@login_required
def note_detail(request, pk: int):
    try:
        note = Note.objects.get(pk=pk)
    except Note.DoesNotExist:
        raise Http404
    return JsonResponse({"title": note.title})
