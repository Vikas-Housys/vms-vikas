from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Visitor, Turnstile, TurnstileLog
from employee.models import Role
from .serializers import VisitorSerializer, TurnstileSerializer, TurnstileLogSerializer


# Custom Permission to Check Role-Based Access
class VisitorViewSet(viewsets.ModelViewSet):
    # permission_classes = [IsAuthenticated]
    queryset = Visitor.objects.all()
    serializer_class = VisitorSerializer

# Turnstile ViewSet
class TurnstileViewSet(viewsets.ModelViewSet):
    # permission_classes = [IsAuthenticated]
    queryset = Turnstile.objects.all()
    serializer_class = TurnstileSerializer


# TurnstileLog ViewSet
class TurnstileLogViewSet(viewsets.ModelViewSet):
    # permission_classes = [IsAuthenticated]
    queryset = TurnstileLog.objects.all()
    serializer_class = TurnstileLogSerializer
