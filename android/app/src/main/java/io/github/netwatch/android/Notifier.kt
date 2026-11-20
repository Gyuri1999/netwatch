package io.github.netwatch.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object Notifier {
    private const val CHANNEL = "alerts"

    fun ensureChannel(ctx: Context) {
        val ch = NotificationChannel(CHANNEL, ctx.getString(R.string.channel_name), NotificationManager.IMPORTANCE_HIGH)
        ch.description = ctx.getString(R.string.channel_desc)
        ctx.getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    fun show(ctx: Context, items: List<AlertItem>) {
        val nm = NotificationManagerCompat.from(ctx)
        if (items.isEmpty() || !nm.areNotificationsEnabled()) return
        ensureChannel(ctx)
        val open = PendingIntent.getActivity(ctx, 0,
            Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val shown = items.takeLast(4)
        for (a in shown) {
            val n = NotificationCompat.Builder(ctx, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(a.type)
                .setContentText(if (a.target.isNotEmpty()) "${a.actor} → ${a.target}" else a.actor)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setContentIntent(open)
                .setAutoCancel(true)
                .apply { if (a === shown.last() && items.size > shown.size)
                    setSubText(ctx.getString(R.string.notif_more, items.size - shown.size)) }
                .build()
            try {
                nm.notify((a.id.ifEmpty { a.t.toString() }).hashCode(), n)
            } catch (e: SecurityException) {
                return  // ο χρήστης αφαίρεσε την άδεια ειδοποιήσεων
            }
        }
    }
}
