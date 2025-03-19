from rest_framework import serializers
from .models import VisitorDetails, VisitorDocuments, VisitorPerson


class VisitorDocumentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = VisitorDocuments
        fields = '__all__'


class VisitorPersonSerializer(serializers.ModelSerializer):
    class Meta:
        model = VisitorPerson
        fields = '__all__'


class VisitorDetailsSerializer(serializers.ModelSerializer):
    documents = VisitorDocumentsSerializer(many=True, read_only=True)
    visits = VisitorPersonSerializer(many=True, read_only=True)

    class Meta:
        model = VisitorDetails
        fields = '__all__'

