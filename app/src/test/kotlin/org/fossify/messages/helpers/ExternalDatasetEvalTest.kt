package org.fossify.messages.helpers

import org.junit.Test
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.PushbackReader
import java.nio.charset.StandardCharsets
import java.util.Locale

class ExternalDatasetEvalTest {

    companion object {
        private const val DATASET_RESOURCE = "/pak_spam_repaired_excel_safe.csv"
        private const val SENDER_MOBILE = "+923001234567"
        private const val SENDER_ALPHANUMERIC = "INFO"

        private const val THRESHOLD_30 = 30
        private const val THRESHOLD_50 = 50
        private const val THRESHOLD_60 = 60
        private const val THRESHOLD_70 = 70
        private const val PERCENT_MULTIPLIER = 100.0
    }

    private data class ExternalRow(
        val text: String,
        val isSpam: Boolean,
        val scamType: String,
        val language: String,
        val urlPresent: String,
    )

    private data class ParseOutput(
        val rows: List<ExternalRow>,
        val failedParseCount: Int,
        val spamLabelCounts: Map<String, Int>,
        val languageCounts: Map<String, Int>,
        val scamTypeCounts: Map<String, Int>,
    )

    private data class GroupCounts(
        var spamTotal: Int = 0,
        var spamCaught60: Int = 0,
        var hamTotal: Int = 0,
        var hamFlagged60: Int = 0,
    )

    private class VariantStats(val senderName: String) {
        var totalRows = 0
        var spamRows = 0
        var hamRows = 0

        var spamAt30 = 0
        var spamAt50 = 0
        var spamAt60 = 0
        var spamAt70 = 0

        var hamAt30 = 0
        var hamAt50 = 0
        var hamAt60 = 0
        var hamAt70 = 0

        val byLanguage = mutableMapOf<String, GroupCounts>()
        val byScamType = mutableMapOf<String, GroupCounts>()
        val byUrlPresent = mutableMapOf<String, GroupCounts>()
    }

    @Test
    fun evaluateExternalDatasetBlind() {
        val stream = javaClass.getResourceAsStream(DATASET_RESOURCE)
        if (stream == null) {
            println("Skipping ExternalDatasetEvalTest: $DATASET_RESOURCE not found in test resources.")
            return
        }

        val parsed = parseDataset(stream)
        printLabelDistributions(parsed)

        val mobileStats = evaluateWithSender(SENDER_MOBILE, parsed.rows)
        val infoStats = evaluateWithSender(SENDER_ALPHANUMERIC, parsed.rows)

        printVariantReport(mobileStats)
        printVariantReport(infoStats)
    }

    private data class ColumnIndices(
        val headerSize: Int,
        val text: Int,
        val spam: Int,
        val scamType: Int,
        val language: Int,
        val urlPresent: Int,
        val minRequiredCols: Int,
    )

    private fun parseDataset(stream: InputStream): ParseOutput {
        val pushback = PushbackReader(BufferedReader(InputStreamReader(stream, StandardCharsets.UTF_8)), 2)
        stripBom(pushback)

        val header = readNextCsvRow(pushback)?.map { it.trim().lowercase(Locale.ROOT) }
            ?: return ParseOutput(emptyList(), 0, emptyMap(), emptyMap(), emptyMap())

        val cols = ColumnIndices(
            headerSize = header.size,
            text = header.indexOf("text"),
            spam = header.indexOf("spam"),
            scamType = header.indexOf("scam_type"),
            language = header.indexOf("language"),
            urlPresent = header.indexOf("url_present"),
            minRequiredCols = maxOf(
                header.indexOf("text"),
                header.indexOf("spam"),
                header.indexOf("scam_type"),
                header.indexOf("language"),
                header.indexOf("url_present")
            ) + 1
        )

        val rows = mutableListOf<ExternalRow>()
        var failedCount = 0
        val spamCounts = mutableMapOf<String, Int>()
        val langCounts = mutableMapOf<String, Int>()
        val scamCounts = mutableMapOf<String, Int>()

        var rawRow = readNextCsvRow(pushback)
        while (rawRow != null) {
            if (!(rawRow.size == 1 && rawRow[0].isEmpty())) {
                val parsedRow = parseSingleRow(rawRow, cols, spamCounts, langCounts, scamCounts)
                if (parsedRow != null) {
                    rows.add(parsedRow)
                } else {
                    failedCount++
                }
            }
            rawRow = readNextCsvRow(pushback)
        }
        return ParseOutput(rows, failedCount, spamCounts, langCounts, scamCounts)
    }

    private fun parseSingleRow(
        rawRow: List<String>,
        cols: ColumnIndices,
        spamCounts: MutableMap<String, Int>,
        langCounts: MutableMap<String, Int>,
        scamCounts: MutableMap<String, Int>,
    ): ExternalRow? {
        if (rawRow.size < cols.minRequiredCols || rawRow.size != cols.headerSize) {
            return null
        }
        val spamRaw = rawRow[cols.spam].trim().lowercase(Locale.ROOT)
        val isSpam = mapSpamLabel(spamRaw) ?: return null

        val scamType = rawRow[cols.scamType].trim()
        val language = rawRow[cols.language].trim()
        val urlPresent = rawRow[cols.urlPresent].trim().lowercase(Locale.ROOT)

        spamCounts[spamRaw] = (spamCounts[spamRaw] ?: 0) + 1
        langCounts[language] = (langCounts[language] ?: 0) + 1
        scamCounts[scamType] = (scamCounts[scamType] ?: 0) + 1

        return ExternalRow(
            text = rawRow[cols.text],
            isSpam = isSpam,
            scamType = scamType,
            language = language,
            urlPresent = urlPresent
        )
    }

    private fun mapSpamLabel(raw: String): Boolean? {
        return when (raw) {
            "spam" -> true
            "ham" -> false
            else -> null
        }
    }

    private fun stripBom(reader: PushbackReader) {
        val first = reader.read()
        if (first != -1 && first != '\uFEFF'.code) {
            reader.unread(first)
        }
    }

    private fun readNextCsvRow(reader: PushbackReader): List<String>? {
        val row = mutableListOf<String>()
        val field = StringBuilder()
        var inQuotes = false
        var sawAnyChar = false
        var rowDone = false

        var code = reader.read()
        while (code != -1 && !rowDone) {
            sawAnyChar = true
            val ch = code.toChar()
            if (inQuotes) {
                inQuotes = handleQuotedChar(ch, reader, field)
            } else {
                rowDone = handleUnquotedChar(ch, reader, row, field) { inQuotes = true }
            }
            if (!rowDone) {
                code = reader.read()
            }
        }

        if (!sawAnyChar) return null
        if (!rowDone) row.add(field.toString())
        return row
    }

    private fun handleQuotedChar(ch: Char, reader: PushbackReader, field: StringBuilder): Boolean {
        var stillInQuotes = true
        if (ch != '"') {
            field.append(ch)
        } else {
            val next = reader.read()
            if (next == '"'.code) {
                field.append('"')
            } else {
                if (next != -1) reader.unread(next)
                stillInQuotes = false
            }
        }
        return stillInQuotes
    }

    private fun handleUnquotedChar(
        ch: Char,
        reader: PushbackReader,
        row: MutableList<String>,
        field: StringBuilder,
        onStartQuote: () -> Unit,
    ): Boolean {
        var endOfRow = false
        when {
            ch == '"' && field.isEmpty() -> onStartQuote()
            ch == ',' -> {
                row.add(field.toString())
                field.setLength(0)
            }
            ch == '\r' -> {
                val next = reader.read()
                if (next != '\n'.code && next != -1) reader.unread(next)
                row.add(field.toString())
                endOfRow = true
            }
            ch == '\n' -> {
                row.add(field.toString())
                endOfRow = true
            }
            else -> field.append(ch)
        }
        return endOfRow
    }

    private fun evaluateWithSender(sender: String, rows: List<ExternalRow>): VariantStats {
        val stats = VariantStats(sender)
        for (row in rows) {
            val score = SpamScorer.score(sender, row.text).score
            stats.totalRows++
            if (row.isSpam) {
                recordSpamScore(stats, row, score)
            } else {
                recordHamScore(stats, row, score)
            }
        }
        return stats
    }

    private fun recordSpamScore(stats: VariantStats, row: ExternalRow, score: Int) {
        stats.spamRows++
        if (score >= THRESHOLD_30) stats.spamAt30++
        if (score >= THRESHOLD_50) stats.spamAt50++
        if (score >= THRESHOLD_60) stats.spamAt60++
        if (score >= THRESHOLD_70) stats.spamAt70++

        val caught60 = score >= THRESHOLD_60
        incrementGroup(stats.byLanguage, row.language, isSpam = true, flaggedAt60 = caught60)
        incrementGroup(stats.byScamType, row.scamType, isSpam = true, flaggedAt60 = caught60)
        incrementGroup(stats.byUrlPresent, row.urlPresent, isSpam = true, flaggedAt60 = caught60)
    }

    private fun recordHamScore(stats: VariantStats, row: ExternalRow, score: Int) {
        stats.hamRows++
        if (score >= THRESHOLD_30) stats.hamAt30++
        if (score >= THRESHOLD_50) stats.hamAt50++
        if (score >= THRESHOLD_60) stats.hamAt60++
        if (score >= THRESHOLD_70) stats.hamAt70++

        val flagged60 = score >= THRESHOLD_60
        incrementGroup(stats.byLanguage, row.language, isSpam = false, flaggedAt60 = flagged60)
        incrementGroup(stats.byScamType, row.scamType, isSpam = false, flaggedAt60 = flagged60)
        incrementGroup(stats.byUrlPresent, row.urlPresent, isSpam = false, flaggedAt60 = flagged60)
    }

    private fun incrementGroup(
        map: MutableMap<String, GroupCounts>,
        key: String,
        isSpam: Boolean,
        flaggedAt60: Boolean,
    ) {
        val counts = map.getOrPut(key) { GroupCounts() }
        if (isSpam) {
            counts.spamTotal++
            if (flaggedAt60) counts.spamCaught60++
        } else {
            counts.hamTotal++
            if (flaggedAt60) counts.hamFlagged60++
        }
    }

    private fun printLabelDistributions(parsed: ParseOutput) {
        println("==================================================")
        println("  EXTERNAL DATASET PARSE & LABEL DISTRIBUTION")
        println("==================================================")
        println("Rows parsed successfully: ${parsed.rows.size}")
        println("Rows failed to parse: ${parsed.failedParseCount}")
        println("Label mapping: 'spam' -> true, 'ham' -> false")
        println("Distinct 'spam' counts: ${parsed.spamLabelCounts}")
        println("Distinct 'language' counts: ${parsed.languageCounts}")
        println("Distinct 'scam_type' counts (${parsed.scamTypeCounts.size} types):")
        for ((k, v) in parsed.scamTypeCounts.entries.sortedByDescending { it.value }) {
            println("  $k: $v")
        }
    }

    private fun printVariantReport(s: VariantStats) {
        println("==================================================")
        println("  VARIANT REPORT (Fixed Stand-In Sender: ${s.senderName})")
        println("==================================================")
        println("Total rows: ${s.totalRows} | Spam rows: ${s.spamRows} | Legitimate rows: ${s.hamRows}")
        println("Spam caught >= 30: ${s.spamAt30}/${s.spamRows} (${pct(s.spamAt30, s.spamRows)})")
        println("Spam caught >= 50: ${s.spamAt50}/${s.spamRows} (${pct(s.spamAt50, s.spamRows)})")
        println("Spam caught >= 60: ${s.spamAt60}/${s.spamRows} (${pct(s.spamAt60, s.spamRows)})")
        println("Spam caught >= 70: ${s.spamAt70}/${s.spamRows} (${pct(s.spamAt70, s.spamRows)})")
        println("Legitimate flagged >= 30: ${s.hamAt30}/${s.hamRows} (${pct(s.hamAt30, s.hamRows)})")
        println("Legitimate flagged >= 50: ${s.hamAt50}/${s.hamRows} (${pct(s.hamAt50, s.hamRows)})")
        println("Legitimate flagged >= 60: ${s.hamAt60}/${s.hamRows} (${pct(s.hamAt60, s.hamRows)})")
        println("Legitimate flagged >= 70: ${s.hamAt70}/${s.hamRows} (${pct(s.hamAt70, s.hamRows)})")

        printBreakdown("BY LANGUAGE (Threshold 60)", s.byLanguage)
        printBreakdown("BY URL_PRESENT (Threshold 60)", s.byUrlPresent)
        printBreakdown("BY SCAM_TYPE (Threshold 60)", s.byScamType)
    }

    private fun printBreakdown(title: String, map: Map<String, GroupCounts>) {
        println("--- $title ---")
        for ((key, c) in map.entries.sortedByDescending { it.value.spamTotal + it.value.hamTotal }) {
            println(
                "  $key: Spam caught ${c.spamCaught60}/${c.spamTotal} (${pct(c.spamCaught60, c.spamTotal)}) | " +
                    "Ham flagged ${c.hamFlagged60}/${c.hamTotal} (${pct(c.hamFlagged60, c.hamTotal)})"
            )
        }
    }

    private fun pct(num: Int, den: Int): String {
        if (den == 0) return "0.00%"
        return "${"%.2f".format(Locale.ROOT, (num.toDouble() / den) * PERCENT_MULTIPLIER)}%"
    }
}
