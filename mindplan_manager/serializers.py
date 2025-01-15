from rest_framework import serializers

from .models import Task


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = (
            "id",
            "owner",
            "title",
            "description",
            "priority",
            "status",
            "start_date",
            "end_date",
        )
