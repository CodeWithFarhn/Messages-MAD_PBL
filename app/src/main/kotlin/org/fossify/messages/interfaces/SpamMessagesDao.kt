package org.fossify.messages.interfaces

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import org.fossify.messages.models.SpamMessage

@Dao
interface SpamMessagesDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertOrUpdate(spamMessage: SpamMessage): Long

    @Query("SELECT * FROM spam_messages ORDER BY date DESC")
    fun getAll(): List<SpamMessage>

    @Query("SELECT * FROM spam_messages WHERE id = :id")
    fun getSpamMessageById(id: Long): SpamMessage?

    @Query("DELETE FROM spam_messages WHERE id = :id")
    fun delete(id: Long): Int

    @Query("DELETE FROM spam_messages WHERE address = :address")
    fun deleteByAddress(address: String): Int

    @Query("DELETE FROM spam_messages")
    fun deleteAll(): Int
}

