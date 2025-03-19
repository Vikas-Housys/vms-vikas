from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from visitor.views import VisitorDetailsViewSet, VisitorDocumentsViewSet, VisitorPersonViewSet

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'visitors', VisitorDetailsViewSet, basename='visitor')
router.register(r'documents', VisitorDocumentsViewSet, basename='document')
router.register(r'visits', VisitorPersonViewSet, basename='visit')

# Define URL patterns
urlpatterns = [
    path('', include(router.urls)),
]

