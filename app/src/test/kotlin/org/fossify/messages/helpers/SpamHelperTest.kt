package org.fossify.messages.helpers

import org.junit.Assert.assertEquals
import org.junit.Test

class SpamHelperTest {

    @Test
    fun testAddressNormalization() {
        // Alphanumeric senders
        assertEquals("tcs", SpamHelper.normalizeSenderAddress("TCS"))
        assertEquals("jazz", SpamHelper.normalizeSenderAddress("  JAZZ  "))
        assertEquals("daraz", SpamHelper.normalizeSenderAddress("Daraz"))

        // Pakistani mobile numbers with various prefixes
        assertEquals("923001234567", SpamHelper.normalizeSenderAddress("+923001234567"))
        assertEquals("923001234567", SpamHelper.normalizeSenderAddress("03001234567"))
        assertEquals("923001234567", SpamHelper.normalizeSenderAddress("00923001234567"))
        assertEquals("923001234567", SpamHelper.normalizeSenderAddress("3001234567"))
        assertEquals("923001234567", SpamHelper.normalizeSenderAddress("+92 300-1234567"))

        // Short codes
        assertEquals("8171", SpamHelper.normalizeSenderAddress("8171"))
        assertEquals("8001", SpamHelper.normalizeSenderAddress("8001"))

        // Blank
        assertEquals("", SpamHelper.normalizeSenderAddress("   "))
    }
}

