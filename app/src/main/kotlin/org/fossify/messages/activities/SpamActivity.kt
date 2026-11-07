package org.fossify.messages.activities

import android.os.Bundle
import org.fossify.commons.dialogs.ConfirmationDialog
import org.fossify.commons.extensions.beVisibleIf
import org.fossify.commons.extensions.toast
import org.fossify.commons.extensions.updateTextColors
import org.fossify.commons.extensions.viewBinding
import org.fossify.commons.helpers.NavigationIcon
import org.fossify.commons.helpers.ensureBackgroundThread
import org.fossify.messages.R
import org.fossify.messages.adapters.SpamAdapter
import org.fossify.messages.databinding.ActivitySpamBinding
import org.fossify.messages.extensions.spamMessagesDB
import org.fossify.messages.extensions.spamSendersDB
import org.fossify.messages.helpers.SmsMessageHelper
import org.fossify.messages.helpers.SpamHelper
import org.fossify.messages.helpers.refreshConversations
import org.fossify.messages.models.SpamMessage
import org.fossify.messages.models.SpamSender

class SpamActivity : SimpleActivity() {

    private val binding by viewBinding(ActivitySpamBinding::inflate)
    private var spamAdapter: SpamAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        setupEdgeToEdge(padBottomImeAndSystem = listOf(binding.spamList))
        setupMaterialScrollListener(
            scrollingView = binding.spamList,
            topAppBar = binding.spamAppbar
        )
        updateTextColors(binding.spamCoordinator)

        setupAdapter()
        setupMenu()
    }

    override fun onResume() {
        super.onResume()
        setupTopAppBar(binding.spamAppbar, NavigationIcon.Arrow)
        loadMessages()
    }

    private fun setupAdapter() {
        spamAdapter = SpamAdapter(
            messages = emptyList(),
            onNotSpam = { message -> handleNotSpam(message) },
            onDelete = { message -> handleDelete(message) }
        )
        binding.spamList.adapter = spamAdapter
    }

    private fun setupMenu() {
        binding.spamToolbar.inflateMenu(R.menu.menu_spam)
        binding.spamToolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.delete_all -> {
                    handleDeleteAll()
                    true
                }
                else -> false
            }
        }
    }

    private fun loadMessages() {
        ensureBackgroundThread {
            val messages = spamMessagesDB.getAll()
            runOnUiThread {
                spamAdapter?.updateMessages(messages)
                binding.noSpamPlaceholder.beVisibleIf(messages.isEmpty())
                binding.spamToolbar.menu.findItem(R.id.delete_all)?.isVisible = messages.isNotEmpty()
            }
        }
    }

    private fun handleNotSpam(message: SpamMessage) {
        ensureBackgroundThread {
            val normalizedAddress = SpamHelper.normalizeSenderAddress(message.address)
            spamSendersDB.insertOrUpdate(
                SpamSender(address = normalizedAddress, status = SpamSender.STATUS_ALLOWED)
            )

            SmsMessageHelper.handleMessageSync(
                context = this@SpamActivity,
                address = message.address,
                body = message.body,
                date = message.date,
                read = 1,
                subscriptionId = message.subscriptionId,
                showNotification = false
            )

            spamMessagesDB.delete(message.id)
            refreshConversations()

            runOnUiThread {
                toast(R.string.message_restored)
                loadMessages()
            }
        }
    }

    private fun handleDelete(message: SpamMessage) {
        ensureBackgroundThread {
            spamMessagesDB.delete(message.id)
            runOnUiThread {
                loadMessages()
            }
        }
    }

    private fun handleDeleteAll() {
        ConfirmationDialog(this, message = getString(R.string.delete_all_spam_confirmation)) {
            ensureBackgroundThread {
                spamMessagesDB.deleteAll()
                runOnUiThread {
                    loadMessages()
                }
            }
        }
    }
}

