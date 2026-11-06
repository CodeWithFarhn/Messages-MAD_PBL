package org.fossify.messages.models

import androidx.room.ColumnInfo
import androidx.room.Entity

@Entity(
    tableName = "starred_messages",
    primaryKeys = ["message_id", "is_mms"]
)
data class StarredMessage(
    @ColumnInfo(name = "message_id") val messageId: Long,
    @ColumnInfo(name = "is_mms") val isMms: Boolean,
    @ColumnInfo(name = "starred_ts") val starredTs: Long,
)
