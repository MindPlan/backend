from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from mindplan_manager.models import Group, Task
from mindplan_manager.serializers import TaskSerializer, GroupSerializer


class TaskViewSet(
    ModelViewSet,
):
    serializer_class = TaskSerializer
    queryset = Task.objects.all()
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Task.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class GroupViewSet(
    ModelViewSet,
):
    serializer_class = GroupSerializer
    queryset = Group.objects.all()
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Group.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
