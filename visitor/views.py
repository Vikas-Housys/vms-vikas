from rest_framework import viewsets
from .models import VisitorDetails, VisitorDocuments, VisitorPerson
from .serializers import VisitorDetailsSerializer, VisitorDocumentsSerializer, VisitorPersonSerializer


class VisitorDetailsViewSet(viewsets.ModelViewSet):
    queryset = VisitorDetails.objects.all().order_by('-created_at')
    serializer_class = VisitorDetailsSerializer


class VisitorDocumentsViewSet(viewsets.ModelViewSet):
    queryset = VisitorDocuments.objects.all().order_by('-created_at')
    serializer_class = VisitorDocumentsSerializer


class VisitorPersonViewSet(viewsets.ModelViewSet):
    queryset = VisitorPerson.objects.all().order_by('-created_at')
    serializer_class = VisitorPersonSerializer

