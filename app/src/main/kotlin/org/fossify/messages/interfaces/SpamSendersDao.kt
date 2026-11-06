package org.fossify.messages.interfaces

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import org.fossify.messages.models.SpamSender

@Dao
interface SpamSendersDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertOrUpdate(spamSender: SpamSender): Long

    @Query("SELECT * FROM spam_senders")
    fun getAll(): List<SpamSender>

    @Query("SELECT status FROM spam_senders WHERE address = :address")
    fun getSenderStatus(address: String): String?

    @Query("DELETE FROM spam_senders WHERE address = :address")
    fun delete(address: String): Int

    @Query("DELETE FROM spam_senders")
    fun deleteAll(): Int
}
