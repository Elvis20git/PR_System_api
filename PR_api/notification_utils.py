from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Notification


def send_notification(user_id, message, pr_id):
    """
    Utility function to send notifications to users
    """
    notification = Notification.objects.create(
        recipient_id=user_id,
        message=message,
        purchase_request_id=pr_id
    )

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{user_id}",
        {
            "type": "notify",
            "data": {
                "id": notification.id,
                "title": notification.message,
                "message": message,
                "purchase_request_id": pr_id,
                "created_at": notification.created_at.isoformat()
            }
        }
    )