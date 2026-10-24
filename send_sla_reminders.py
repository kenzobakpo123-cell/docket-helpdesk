from datetime import timedelta

from app import (
    SLA_TARGET_HOURS,
    Ticket,
    _utc_now,
    app,
    db,
    notify_user,
    push_is_configured,
)


def send_sla_reminders():
    if not push_is_configured():
        raise RuntimeError('VAPID must be configured before SLA reminders can run.')

    now = _utc_now()
    active_tickets = Ticket.query.filter(
        Ticket.status.in_(['open', 'in_progress'])
    ).all()
    sent_count = 0

    for ticket in active_tickets:
        deadline = ticket.created_at + timedelta(
            hours=SLA_TARGET_HOURS.get(ticket.priority, SLA_TARGET_HOURS['medium'])
        )
        if ticket.sla_overdue_sent_at is None and deadline <= now:
            notification = (
                'Target penanganan tiket terlewati',
                'Tiket aktif telah melewati target waktu penanganan.',
            )
            timestamp_field = 'sla_overdue_sent_at'
        elif (
            ticket.sla_reminder_sent_at is None
            and now < deadline <= now + timedelta(hours=1)
        ):
            notification = (
                'Pengingat target tiket',
                'Target waktu penanganan tiket akan tercapai dalam satu jam.',
            )
            timestamp_field = 'sla_reminder_sent_at'
        else:
            continue

        recipient_ids = {ticket.user_id, ticket.assigned_to_id} - {None}
        for recipient_id in recipient_ids:
            notify_user(
                recipient_id,
                notification[0],
                notification[1],
                f'/ticket/{ticket.id}',
                'sla_reminder',
            )

        setattr(ticket, timestamp_field, now)
        db.session.commit()
        sent_count += 1

    return sent_count


if __name__ == '__main__':
    with app.app_context():
        print(f'Pengingat SLA diproses untuk {send_sla_reminders()} tiket.')
