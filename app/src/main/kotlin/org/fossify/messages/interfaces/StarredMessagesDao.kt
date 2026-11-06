package org.fossify.messages.interfaces

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import org.fossify.messages.models.StarredMessage

@Dao
interface StarredMessagesDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertOrUpdate(starredMessage: StarredMessage): Long

    @Query("SELECT * FROM starred_messages ORDER BY starred_ts DESC")
    fun getAll(): List<StarredMessage>

    @Query("SELECT EXISTS(SELECT 1 FROM starred_messages WHERE message_id = :messageId AND is_mms = :isMms)")
    fun isMessageStarred(messageId: Long, isMms: Boolean): Boolean

    @Query("DELETE FROM starred_messages WHERE message_id = :messageId AND is_mms = :isMms")
    fun delete(messageId: Long, isMms: Boolean): Int

    @Query("SELECT * FROM starred_messages WHERE is_mms = :isMms AND message_id IN (:messageIds)")
    fun getStarredByMessageIds(messageIds: List<Long>, isMms: Boolean): List<StarredMessage>

    @Query("DELETE FROM starred_messages")
    fun deleteAll(): Int
}

