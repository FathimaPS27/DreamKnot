from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import UserSignup, WeddingTask

@receiver(post_save, sender=UserSignup)
def create_predefined_tasks(sender, instance, created, **kwargs):
    if created and instance.wedding_date:
        predefined_tasks = WeddingTask.objects.filter(is_predefined=True)
        for task in predefined_tasks:
            WeddingTask.objects.create(
                user=instance,
                description=task.description,
                task_month=task.task_month,
                is_predefined=True
            )
