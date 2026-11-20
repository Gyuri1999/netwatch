package io.github.netwatch.android

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** Κάθε 15 λεπτά (το ελάχιστο του Android): ρωτά τον agent και ειδοποιεί για νέες σοβαρές ειδοποιήσεις. */
class AlertWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result {
        val store = Store(applicationContext)
        val cfg = store.config ?: return Result.success()
        if (!store.notify) return Result.success()
        val status = try {
            AgentClient.status(cfg)
        } catch (e: Exception) {
            return Result.success()  // εκτός σπιτιού ή agent κλειστός: δοκιμάζουμε στον επόμενο κύκλο
        }
        val (items, seen) = Alerts.fresh(status, store.lastSeen)
        store.lastSeen = seen
        Notifier.show(applicationContext, items)
        return Result.success()
    }

    companion object {
        private const val NAME = "netwatch-alerts"

        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<AlertWorker>(15, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun cancel(ctx: Context) = WorkManager.getInstance(ctx).cancelUniqueWork(NAME)
    }
}
