from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import Task, Group


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = ("id", "name", "description", "owner")

class TaskSerializer(serializers.ModelSerializer):

    def validate(self, data):
        """
        Перевірка, чи всі групи завдання належать поточному власнику.
        """
        owner = self.context["request"].user
        error_to_raise = ValidationError

        groups = data.get("group")

        if groups:
            for group in groups:
                Task.validate_group(owner, group, error_to_raise)

        return data

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
