package org.fossify.messages.models

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "spam_senders")
data class SpamSender(
    @PrimaryKey @ColumnInfo(name = "address") val address: String,
    @ColumnInfo(name = "status") val status: String,
) {
    companion object {
        const val STATUS_ALLOWED = "ALLOWED"
        const val STATUS_SPAM = "SPAM"
    }
}
