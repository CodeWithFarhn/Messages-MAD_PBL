package org.fossify.messages.helpers

import java.util.Locale

private const val PAKISTAN_PREFIX_0092_LENGTH = 14
private const val LOCAL_MOBILE_LENGTH = 11
private const val UNPREFIXED_MOBILE_LENGTH = 10

object SpamHelper {

    /**
     * Normalizes a sender address for consistent lookup and storage in spam_senders.
     *
     * - Alphanumeric sender IDs (e.g., "TCS", "Jazz", "Daraz") are trimmed and lowercased.
     * - Phone numbers and short codes have non-digit formatting characters removed.
     * - Pakistani mobile prefixes (+92, 0092, 0) and un-prefixed 3xx numbers are normalized to "923xx...".
     */
    fun normalizeSenderAddress(address: String): String {
        val trimmed = address.trim()
        if (trimmed.isEmpty()) return ""

        if (trimmed.any { it.isLetter() }) {
            return trimmed.lowercase(Locale.ROOT)
        }

        var digits = trimmed.filter { it.isDigit() }
        if (digits.startsWith("0092") && digits.length == PAKISTAN_PREFIX_0092_LENGTH) {
            digits = digits.substring(2)
        }
        if (digits.startsWith("0") && digits.length == LOCAL_MOBILE_LENGTH) {
            digits = "92" + digits.substring(1)
        } else if (digits.length == UNPREFIXED_MOBILE_LENGTH && digits.startsWith("3")) {
            digits = "92$digits"
        }
        return digits
    }
}

