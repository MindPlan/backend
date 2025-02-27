from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import Task, Tag, TaskGroup


class TagSerializer(serializers.ModelSerializer):

    class Meta:
        model = Tag
        fields = ("id", "name")


class TaskGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskGroup
        fields = ("id", "name")


class TaskSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    group = serializers.PrimaryKeyRelatedField(
        queryset=TaskGroup.objects.none(),
        allow_null=True
    )
    tag = serializers.PrimaryKeyRelatedField(many=True, queryset=Tag.objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            self.fields["group"].queryset = TaskGroup.objects.filter(owner=request.user)

    def validate(self, data):
        """
        Перевірка, чи всі групи завдання належать поточному власнику.
        """
        owner = self.context["request"].user
        error_to_raise = ValidationError

        group = data.get("group")
        if not group:
            group = TaskGroup.objects.filter(name="Tasks").first()
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
            "group",
            "tag",
            "start_date",
            "end_date",
        )

    def create(self, validated_data):
        request = self.context.get("request")
        if not validated_data.get("group"):
            default_group = TaskGroup.objects.filter(
                owner=validated_data["owner"], name="Tasks"
            ).first()
            validated_data["group"] = default_group
        validated_data["owner"] = request.user if request else None
        return super().create(validated_data)
