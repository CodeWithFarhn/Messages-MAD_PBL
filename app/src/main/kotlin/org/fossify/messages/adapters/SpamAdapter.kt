package org.fossify.messages.adapters

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import org.fossify.commons.extensions.formatDateOrTime
import org.fossify.commons.extensions.getProperTextColor
import org.fossify.messages.R
import org.fossify.messages.databinding.ItemSpamMessageBinding
import org.fossify.messages.models.SpamMessage

class SpamAdapter(
    private var messages: List<SpamMessage>,
    private val onNotSpam: (SpamMessage) -> Unit,
    private val onDelete: (SpamMessage) -> Unit
) : RecyclerView.Adapter<SpamAdapter.ViewHolder>() {

    fun updateMessages(newMessages: List<SpamMessage>) {
        messages = newMessages
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemSpamMessageBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(messages[position])
    }

    override fun getItemCount() = messages.size

    inner class ViewHolder(private val binding: ItemSpamMessageBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(message: SpamMessage) {
            val context = itemView.context
            val textColor = context.getProperTextColor()

            binding.apply {
                spamSender.text = message.address
                spamSender.setTextColor(textColor)

                spamDate.text = message.date.formatDateOrTime(
                    context = context,
                    hideTimeOnOtherDays = false,
                    showCurrentYear = false
                )
                spamDate.setTextColor(textColor)

                spamSnippet.text = message.body
                spamSnippet.setTextColor(textColor)

                val scoreText = context.getString(R.string.spam_score, message.score)
                val reasonsText = if (message.reasons.isNotBlank()) {
                    "$scoreText • ${message.reasons}"
                } else {
                    scoreText
                }
                spamReasons.text = reasonsText
                spamReasons.setTextColor(textColor)

                spamActionNotSpam.setOnClickListener {
                    onNotSpam(message)
                }

                spamActionDelete.setOnClickListener {
                    onDelete(message)
                }
            }
        }
    }
}

