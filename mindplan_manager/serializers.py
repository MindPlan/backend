from rest_framework import serializers
from .models import Task, Group


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = ("id", "name", "description", "owner")


class TaskSerializer(serializers.ModelSerializer):
    group = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Group.objects.none(),  # Початково порожній queryset
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            user_groups = Group.objects.filter(owner=request.user.id)
            print(user_groups)  # Логування груп користувача
            self.fields["group"].queryset = user_groups

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
