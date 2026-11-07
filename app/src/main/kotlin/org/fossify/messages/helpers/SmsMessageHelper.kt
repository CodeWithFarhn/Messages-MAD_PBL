package org.fossify.messages.helpers

import android.content.Context
import android.provider.Telephony
import org.fossify.commons.extensions.getMyContactsCursor
import org.fossify.commons.helpers.SimpleContactsHelper
import org.fossify.commons.models.PhoneNumber
import org.fossify.commons.models.SimpleContact
import org.fossify.messages.extensions.getConversations
import org.fossify.messages.extensions.getNameFromAddress
import org.fossify.messages.extensions.getNotificationBitmap
import org.fossify.messages.extensions.getThreadId
import org.fossify.messages.extensions.insertNewSMS
import org.fossify.messages.extensions.insertOrUpdateConversation
import org.fossify.messages.extensions.messagesDB
import org.fossify.messages.extensions.shouldUnarchive
import org.fossify.messages.extensions.showReceivedMessageNotification
import org.fossify.messages.extensions.updateConversationArchivedStatus
import org.fossify.messages.models.Message

object SmsMessageHelper {

    fun handleMessageSync(
        context: Context,
        address: String,
        subject: String = "",
        body: String,
        date: Long,
        read: Int = 0,
        threadId: Long = context.getThreadId(address),
        type: Int = Telephony.Sms.MESSAGE_TYPE_INBOX,
        subscriptionId: Int = -1,
        status: Int = Telephony.Sms.STATUS_NONE,
        showNotification: Boolean = true
    ) {
        val photoUri = SimpleContactsHelper(context).getPhotoUriFromPhoneNumber(address)
        val bitmap = context.getNotificationBitmap(photoUri)

        val newMessageId = context.insertNewSMS(
            address = address,
            subject = subject,
            body = body,
            date = date,
            read = read,
            threadId = threadId,
            type = type,
            subscriptionId = subscriptionId
        )

        context.getConversations(threadId).firstOrNull()?.let { conv ->
            runCatching { context.insertOrUpdateConversation(conv) }
        }

        val senderName = context.getMyContactsCursor(favoritesOnly = false, withPhoneNumbersOnly = true).use {
            context.getNameFromAddress(address, it)
        }

        val participant = SimpleContact(
            rawId = 0,
            contactId = 0,
            name = senderName,
            photoUri = photoUri,
            phoneNumbers = arrayListOf(
                PhoneNumber(
                    value = address,
                    type = 0,
                    label = "",
                    normalizedNumber = address
                )
            ),
            birthdays = ArrayList(),
            anniversaries = ArrayList()
        )

        val message = Message(
            id = newMessageId,
            body = body,
            type = type,
            status = status,
            participants = arrayListOf(participant),
            date = (date / 1000).toInt(),
            read = read == 1,
            threadId = threadId,
            isMMS = false,
            attachment = null,
            senderPhoneNumber = address,
            senderName = senderName,
            senderPhotoUri = photoUri,
            subscriptionId = subscriptionId
        )

        context.messagesDB.insertOrUpdate(message)

        if (context.shouldUnarchive()) {
            context.updateConversationArchivedStatus(threadId, false)
        }

        refreshMessages()
        refreshConversations()

        if (showNotification) {
            context.showReceivedMessageNotification(
                messageId = newMessageId,
                isMms = false,
                address = address,
                senderName = senderName,
                body = body,
                threadId = threadId,
                bitmap = bitmap
            )
        }
    }
}

