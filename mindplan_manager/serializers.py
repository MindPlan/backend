from rest_framework import serializers
from .models import Task, Group


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = ("id", "name", "description", "owner")


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
            "group",
            "start_date",
            "end_date",
        )
