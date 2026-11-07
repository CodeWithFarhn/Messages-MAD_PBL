package org.fossify.messages.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import org.fossify.commons.extensions.baseConfig
import org.fossify.commons.extensions.getMyContactsCursor
import org.fossify.commons.extensions.isNumberBlocked
import org.fossify.commons.helpers.ContactLookupResult
import org.fossify.commons.helpers.SimpleContactsHelper
import org.fossify.commons.helpers.ensureBackgroundThread
import org.fossify.messages.extensions.config
import org.fossify.messages.extensions.getThreadId
import org.fossify.messages.extensions.spamMessagesDB
import org.fossify.messages.extensions.spamSendersDB
import org.fossify.messages.helpers.ReceiverUtils.isMessageFilteredOut
import org.fossify.messages.helpers.SmsMessageHelper
import org.fossify.messages.helpers.SpamHelper
import org.fossify.messages.helpers.SpamScorer
import org.fossify.messages.models.SpamMessage
import org.fossify.messages.models.SpamSender

private const val SENDER_SPAM_SCORE = 100

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        val appContext = context.applicationContext

        ensureBackgroundThread {
            try {
                val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)
                if (parts.isEmpty()) return@ensureBackgroundThread

                val address = parts.last().originatingAddress.orEmpty()
                if (address.isBlank()) return@ensureBackgroundThread
                val subject = parts.last().pseudoSubject.orEmpty()
                val status = parts.last().status
                val body = buildString { parts.forEach { append(it.messageBody.orEmpty()) } }

                // 1. Existing blocked number and keyword checks first, unchanged
                if (isMessageFilteredOut(appContext, body)) return@ensureBackgroundThread
                if (appContext.isNumberBlocked(address)) return@ensureBackgroundThread
                if (appContext.baseConfig.blockUnknownNumbers) {
                    val privateCursor =
                        appContext.getMyContactsCursor(favoritesOnly = false, withPhoneNumbersOnly = true)
                    val result = SimpleContactsHelper(appContext).existsSync(address, privateCursor)
                    if (result == ContactLookupResult.NotFound) return@ensureBackgroundThread
                }

                val date = System.currentTimeMillis()
                val subscriptionId = intent.getIntExtra("subscription", -1)

                // 2. Spam checks before getThreadId and insertNewSMS
                if (shouldQuarantineSpam(appContext, address, body, date, subscriptionId)) {
                    return@ensureBackgroundThread
                }

                val threadId = appContext.getThreadId(address)
                SmsMessageHelper.handleMessageSync(
                    context = appContext,
                    address = address,
                    subject = subject,
                    body = body,
                    date = date,
                    threadId = threadId,
                    subscriptionId = subscriptionId,
                    status = status,
                    showNotification = true
                )
            } finally {
                pending.finish()
            }
        }
    }

    private fun shouldQuarantineSpam(
        context: Context,
        address: String,
        body: String,
        date: Long,
        subscriptionId: Int
    ): Boolean {
        val config = context.config
        if (!config.isSpamFilterEnabled) {
            return false
        }

        val isSavedContact = context.getMyContactsCursor(favoritesOnly = false, withPhoneNumbersOnly = true).use {
            SimpleContactsHelper(context).existsSync(address, it) != ContactLookupResult.NotFound
        }
        if (isSavedContact) {
            return false
        }

        val normalizedAddress = SpamHelper.normalizeSenderAddress(address)
        val senderStatus = context.spamSendersDB.getSenderStatus(normalizedAddress)
        if (senderStatus == SpamSender.STATUS_ALLOWED) {
            return false
        }

        val isMarkedSpam = senderStatus == SpamSender.STATUS_SPAM
        val scorerResult = if (!isMarkedSpam) SpamScorer.score(address, body) else null
        val shouldQuarantine = isMarkedSpam ||
            (scorerResult != null && scorerResult.score >= config.spamSensitivity)

        if (shouldQuarantine) {
            val score = if (isMarkedSpam) SENDER_SPAM_SCORE else scorerResult!!.score
            val reasons = if (isMarkedSpam) {
                "Sender marked as spam"
            } else {
                scorerResult!!.reasons.joinToString("; ")
            }
            quarantine(context, address, body, date, subscriptionId, score, reasons)
        }

        return shouldQuarantine
    }

    private fun quarantine(
        context: Context,
        address: String,
        body: String,
        date: Long,
        subscriptionId: Int,
        score: Int,
        reasons: String
    ) {
        val spamMessage = SpamMessage(
            address = address,
            body = body,
            date = date,
            subscriptionId = subscriptionId,
            score = score,
            reasons = reasons
        )
        context.spamMessagesDB.insertOrUpdate(spamMessage)
    }
}
