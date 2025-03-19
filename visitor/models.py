from django.db import models

# Visitor Model
class VisitorDetails(models.Model):
    visitor_id = models.AutoField(primary_key=True)
    visitor_name = models.CharField(max_length=100, null=False)
    visitor_email = models.EmailField(unique=True, null=False)
    visitor_mobile = models.CharField(max_length=15, unique=True, null=False)
    organization_name = models.CharField(max_length=255, null=True, blank=True)
    visitor_address = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.visitor_name} ({self.visitor_email}) ({self.visitor_mobile})"


# Visitor Documents Model
class VisitorDocuments(models.Model):
    visitor_document_id = models.AutoField(primary_key=True)
    visitor = models.ForeignKey(VisitorDetails, on_delete=models.CASCADE, related_name="documents")
    visitor_document_name = models.CharField(max_length=100, null=False)
    visitor_document_photo = models.ImageField(upload_to="visitor_documents/")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.visitor_document_name} - {self.visitor.visitor_name}"


# Visitor Person Model
class VisitorPerson(models.Model):
    person_id = models.AutoField(primary_key=True)
    visitor = models.ForeignKey(VisitorDetails, on_delete=models.CASCADE, related_name="visits")
    person_name = models.CharField(max_length=100, null=False)
    person_department = models.CharField(max_length=255, null=False)
    meeting_purpose = models.CharField(max_length=512, null=False)
    meeting_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Meeting with {self.person_name} ({self.person_department}) for {self.meeting_purpose}"

