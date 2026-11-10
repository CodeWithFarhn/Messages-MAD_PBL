package org.fossify.messages.helpers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.Locale

class SpamScorerTest {

    data class Sample(
        val label: String,
        val address: String,
        val body: String,
    )

    data class EvaluationResult(
        val totalSpam: Int,
        val totalHam: Int,
        val truePositives: Int,
        val falseNegatives: Int,
        val trueNegatives: Int,
        val falsePositives: Int,
        val suspiciousHam: Int,
        val suspiciousSpam: Int,
        val missedSpam: List<Pair<Sample, SpamScorer.SpamResult>>,
        val wronglyFlaggedHam: List<Pair<Sample, SpamScorer.SpamResult>>,
        val suspiciousHamList: List<Pair<Sample, SpamScorer.SpamResult>>,
        val suspiciousSpamList: List<Pair<Sample, SpamScorer.SpamResult>>,
    ) {
        val recall: Double
            get() = if (totalSpam > 0) (truePositives.toDouble() / totalSpam) * 100.0 else 100.0

        val precision: Double
            get() = if (truePositives + falsePositives > 0) {
                (truePositives.toDouble() / (truePositives + falsePositives)) * 100.0
            } else 100.0
    }

    private fun loadSamples(): Triple<List<Sample>, List<Sample>, List<Sample>> {
        val inputStream = javaClass.getResourceAsStream("/spam_samples.tsv")
        assertNotNull("spam_samples.tsv must exist in test resources", inputStream)

        val reader = InputStreamReader(inputStream!!, StandardCharsets.UTF_8)
        val lines = reader.readLines()

        val spamList = mutableListOf<Sample>()
        val hamList = mutableListOf<Sample>()
        val borderlineList = mutableListOf<Sample>()

        val validLines = lines.drop(1).filter { it.isNotBlank() }
        for (line in validLines) {
            val parts = line.split("\t")
            if (parts.size >= 3) {
                val sample = Sample(
                    label = parts[0].trim(),
                    address = parts[1].trim(),
                    body = parts[2].trim()
                )

                when (sample.label) {
                    "SPAM" -> spamList.add(sample)
                    "HAM" -> hamList.add(sample)
                    "BORDERLINE" -> borderlineList.add(sample)
                }
            }
        }

        return Triple(spamList, hamList, borderlineList)
    }

    private fun loadBlindSamples(): Triple<List<Sample>, List<Sample>, List<Sample>> {
        val inputStream = javaClass.getResourceAsStream("/spam_samples_blind.tsv")
        assertNotNull("spam_samples_blind.tsv must exist in test resources", inputStream)

        val reader = InputStreamReader(inputStream!!, StandardCharsets.UTF_8)
        val lines = reader.readLines().filter { it.isNotBlank() }
        assertTrue("Blind test file must contain at least a header and samples", lines.size >= 2)

        val header = lines.first().split("\t").map { it.trim().lowercase(Locale.ROOT) }
        val senderIdx = header.indexOf("sender")
        val bodyIdx = header.indexOf("body")
        val labelIdx = header.indexOf("label")

        assertTrue("Header must contain 'sender'", senderIdx >= 0)
        assertTrue("Header must contain 'body'", bodyIdx >= 0)
        assertTrue("Header must contain 'label'", labelIdx >= 0)

        val spamList = mutableListOf<Sample>()
        val hamList = mutableListOf<Sample>()
        val borderlineList = mutableListOf<Sample>()

        for (line in lines.drop(1)) {
            val parts = line.split("\t")
            val maxIdx = maxOf(senderIdx, bodyIdx, labelIdx)
            if (parts.size > maxIdx) {
                val label = parts[labelIdx].trim().uppercase(Locale.ROOT)
                val sample = Sample(
                    label = label,
                    address = parts[senderIdx].trim(),
                    body = parts[bodyIdx].trim()
                )
                when (label) {
                    "SPAM" -> spamList.add(sample)
                    "HAM" -> hamList.add(sample)
                    "BORDERLINE" -> borderlineList.add(sample)
                }
            }
        }

        return Triple(spamList, hamList, borderlineList)
    }

    private fun evaluate(
        spamSet: List<Sample>,
        hamSet: List<Sample>,
        threshold: Int = SpamScorer.THRESHOLD_SPAM
    ): EvaluationResult {
        var tp = 0
        var fn = 0
        var tn = 0
        var fp = 0
        var suspiciousHam = 0
        var suspiciousSpam = 0

        val missedSpam = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()
        val wronglyFlaggedHam = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()
        val suspiciousHamList = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()
        val suspiciousSpamList = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()

        for (sample in spamSet) {
            val result = SpamScorer.score(sample.address, sample.body)
            if (result.score >= threshold) {
                tp++
            } else {
                fn++
                missedSpam.add(Pair(sample, result))
                if (result.score in SpamScorer.THRESHOLD_SUSPICIOUS until threshold) {
                    suspiciousSpam++
                    suspiciousSpamList.add(Pair(sample, result))
                }
            }
        }

        for (sample in hamSet) {
            val result = SpamScorer.score(sample.address, sample.body)
            if (result.score >= threshold) {
                fp++
                wronglyFlaggedHam.add(Pair(sample, result))
            } else {
                tn++
                if (result.score in SpamScorer.THRESHOLD_SUSPICIOUS until threshold) {
                    suspiciousHam++
                    suspiciousHamList.add(Pair(sample, result))
                }
            }
        }

        return EvaluationResult(
            totalSpam = spamSet.size,
            totalHam = hamSet.size,
            truePositives = tp,
            falseNegatives = fn,
            trueNegatives = tn,
            falsePositives = fp,
            suspiciousHam = suspiciousHam,
            suspiciousSpam = suspiciousSpam,
            missedSpam = missedSpam,
            wronglyFlaggedHam = wronglyFlaggedHam,
            suspiciousHamList = suspiciousHamList,
            suspiciousSpamList = suspiciousSpamList
        )
    }

    private fun printReport(title: String, res: EvaluationResult) {
        println("==================================================")
        println("  $title")
        println("==================================================")
        println("Samples: ${res.totalSpam} Spam, ${res.totalHam} Ham (Total: ${res.totalSpam + res.totalHam})")
        println("Confusion Matrix:")
        println("  [True Positive (Spam Caught): ${res.truePositives}, False Negative (Missed): ${res.falseNegatives}]")
        println(
            "  [False Positive (Wrongly Flagged): ${res.falsePositives}, True Negative (Clean): ${res.trueNegatives}]"
        )
        println("Spam Recall: %.1f%% (%d/%d)".format(res.recall, res.truePositives, res.totalSpam))
        val totalFlagged = res.truePositives + res.falsePositives
        println("Precision: %.1f%% (%d/%d)".format(res.precision, res.truePositives, totalFlagged))
        println("Wrongly Flagged Legitimate (score >= 60): ${res.falsePositives} / ${res.totalHam}")
        println("Suspicious Legitimate (score 30..59): ${res.suspiciousHam} / ${res.totalHam}")
        println(
            "Suspicious Spam (score 30..59, caught as suspicious but < 60): " +
                "${res.suspiciousSpam} / ${res.totalSpam}"
        )

        if (res.wronglyFlaggedHam.isNotEmpty()) {
            println("\n--- WRONGLY FLAGGED LEGITIMATE MESSAGES (FALSE POSITIVES) ---")
            for ((sample, result) in res.wronglyFlaggedHam) {
                println("  From: ${sample.address}")
                println("  Body: ${sample.body}")
                println("  Score: ${result.score} (Threshold: ${SpamScorer.THRESHOLD_SPAM})")
                println("  Reasons: ${result.reasons.joinToString(", ")}")
                println()
            }
        }

        if (res.suspiciousHamList.isNotEmpty()) {
            println("\n--- SUSPICIOUS LEGITIMATE MESSAGES (30..59) ---")
            for ((sample, result) in res.suspiciousHamList) {
                println("  From: ${sample.address}")
                println("  Body: ${sample.body}")
                println("  Score: ${result.score}")
                println("  Reasons: ${result.reasons.joinToString(", ")}")
                println()
            }
        }

        if (res.missedSpam.isNotEmpty()) {
            println("\n--- MISSED SPAM MESSAGES (FALSE NEGATIVES) ---")
            for ((sample, result) in res.missedSpam) {
                println("  From: ${sample.address}")
                println("  Body: ${sample.body}")
                println("  Score: ${result.score}")
                println("  Reasons: ${result.reasons.joinToString(", ")}")
                println()
            }
        }
        println()
    }

    private fun isMobileNumber(address: String): Boolean {
        val clean = address.trim().replace(Regex("[\\s-+()]"), "")
        return clean.length >= 10 && clean.all { it.isDigit() }
    }

    private fun printSenderBreakdown(spamList: List<Sample>, hamList: List<Sample>) {
        println("--------------------------------------------------")
        println("  SENDER TYPE BREAKDOWN")
        println("--------------------------------------------------")

        val mobileSpam = spamList.filter { isMobileNumber(it.address) }
        val nonMobileSpam = spamList.filter { !isMobileNumber(it.address) }
        val mobileHam = hamList.filter { isMobileNumber(it.address) }
        val nonMobileHam = hamList.filter { !isMobileNumber(it.address) }

        val mobileResult = evaluate(mobileSpam, mobileHam)
        println("Ordinary Mobile Numbers (+92 3xx...):")
        println(
            "  Spam count: ${mobileSpam.size}, Caught: ${mobileResult.truePositives}, " +
                "Missed: ${mobileResult.falseNegatives}"
        )
        println(
            "  Spam Recall: %.1f%% (%d/%d)".format(
                mobileResult.recall,
                mobileResult.truePositives,
                mobileSpam.size
            )
        )
        println(
            "  Ham count: ${mobileHam.size}, Clean: ${mobileResult.trueNegatives}, " +
                "Suspicious: ${mobileResult.suspiciousHam}, Wrongly Flagged: ${mobileResult.falsePositives}"
        )

        val nonMobileResult = evaluate(nonMobileSpam, nonMobileHam)
        println("Alphanumeric / Shortcode Senders:")
        println(
            "  Spam count: ${nonMobileSpam.size}, Caught: ${nonMobileResult.truePositives}, " +
                "Missed: ${nonMobileResult.falseNegatives}"
        )
        println(
            "  Spam Recall: %.1f%% (%d/%d)".format(
                nonMobileResult.recall,
                nonMobileResult.truePositives,
                nonMobileSpam.size
            )
        )
        println(
            "  Ham count: ${nonMobileHam.size}, Clean: ${nonMobileResult.trueNegatives}, " +
                "Suspicious: ${nonMobileResult.suspiciousHam}, Wrongly Flagged: ${nonMobileResult.falsePositives}"
        )
        println("--------------------------------------------------\n")
    }

    private fun printThresholdSweep(
        setName: String,
        spamSet: List<Sample>,
        hamSet: List<Sample>,
        thresholds: List<Int>
    ) {
        println("=== THRESHOLD SWEEP: $setName ===")
        println("| Threshold | Spam Caught (Recall) | Legitimate Wrongly Flagged (FP) |")
        println("|:---------:|:--------------------:|:-------------------------------:|")
        for (t in thresholds) {
            val res = evaluate(spamSet, hamSet, t)
            val recallStr = "%.1f%% (%d/%d)".format(res.recall, res.truePositives, res.totalSpam)
            val fpStr = "%.1f%% (%d/%d)".format(
                if (res.totalHam > 0) (res.falsePositives.toDouble() / res.totalHam) * 100.0 else 0.0,
                res.falsePositives,
                res.totalHam
            )
            println("|    $t     |   $recallStr   |          $fpStr           |")
        }

        // Top 5 highest scoring legitimate messages
        val scoredHam = hamSet.map { it to SpamScorer.score(it.address, it.body) }
            .sortedByDescending { it.second.score }
            .take(5)

        println("\nTop 5 Highest-Scoring Legitimate Messages in $setName:")
        for ((sample, result) in scoredHam) {
            println("  [Score: ${result.score}] ${sample.address}: ${sample.body}")
            println("   Reasons: ${result.reasons.joinToString(", ")}")
        }
        println()
    }

    @Test
    fun testSpamScorerAccuracyOnTuningAndHeldOutSets() {
        val (allSpam, allHam, borderline) = loadSamples()

        assertTrue("Dataset must contain at least 120 total samples", (allSpam.size + allHam.size) >= 120)

        // 60/40 split assigned by sequential index
        val spamTuningCount = (allSpam.size * 0.6).toInt()
        val hamTuningCount = (allHam.size * 0.6).toInt()

        val spamTuning = allSpam.take(spamTuningCount)
        val spamHeldOut = allSpam.drop(spamTuningCount)

        val hamTuning = allHam.take(hamTuningCount)
        val hamHeldOut = allHam.drop(hamTuningCount)

        // Evaluate Tuning Set
        val tuningResult = evaluate(spamTuning, hamTuning)
        printReport("TUNING SET EVALUATION (60% split by sequential index)", tuningResult)

        // Evaluate Held-out Set
        val heldOutResult = evaluate(spamHeldOut, hamHeldOut)
        printReport("HELD-OUT SET EVALUATION (40% split by sequential index)", heldOutResult)

        // Print Borderline scores for reference (not counted in accuracy metrics)
        println("==================================================")
        println("  BORDERLINE / AMBIGUOUS MESSAGES (REFERENCE ONLY)")
        println("==================================================")
        for (sample in borderline) {
            val res = SpamScorer.score(sample.address, sample.body)
            val flag = when {
                res.isSpam -> "SPAM"
                res.score >= SpamScorer.THRESHOLD_SUSPICIOUS -> "SUSPICIOUS"
                else -> "CLEAN"
            }
            println("[$flag | Score: ${res.score}] ${sample.address}: ${sample.body}")
        }
        println()

        // Threshold Sweeps
        val thresholds = listOf(40, 45, 50, 55, 60, 65, 70)
        printThresholdSweep("Tuning Set (60%)", spamTuning, hamTuning, thresholds)
        printThresholdSweep("Held-Out Set (40%)", spamHeldOut, hamHeldOut, thresholds)

        // Assertions on tuning and held-out thresholds
        assertEquals(
            "Tuning set must have 0 wrongly-flagged legitimate messages",
            0,
            tuningResult.falsePositives
        )
        assertTrue(
            "Tuning set spam recall must be >= 80%, was ${tuningResult.recall}%",
            tuningResult.recall >= 80.0
        )

        assertEquals(
            "Held-out set must have 0 wrongly-flagged legitimate messages",
            0,
            heldOutResult.falsePositives
        )
        assertTrue(
            "Held-out set spam recall must be >= 80%, was ${heldOutResult.recall}%",
            heldOutResult.recall >= 80.0
        )
    }

    @Test
    fun testSpamScorerOnBlindDataset() {
        val (blindSpam, blindHam, blindBorderline) = loadBlindSamples()

        val blindResult = evaluate(blindSpam, blindHam)
        printReport("BLIND DATASET EVALUATION (ROUND 2 - TUNED ON BLIND SET)", blindResult)
        printSenderBreakdown(blindSpam, blindHam)

        val thresholds = listOf(40, 45, 50, 55, 60, 65, 70)
        printThresholdSweep("Blind Dataset", blindSpam, blindHam, thresholds)

        if (blindBorderline.isNotEmpty()) {
            println("==================================================")
            println("  BLIND BORDERLINE MESSAGES (REFERENCE ONLY)")
            println("==================================================")
            for (sample in blindBorderline) {
                val res = SpamScorer.score(sample.address, sample.body)
                val flag = when {
                    res.isSpam -> "SPAM"
                    res.score >= SpamScorer.THRESHOLD_SUSPICIOUS -> "SUSPICIOUS"
                    else -> "CLEAN"
                }
                println("[$flag | Score: ${res.score}] ${sample.address}: ${sample.body}")
            }
            println()
        }
    }

    private fun loadRound3Samples(): Pair<List<Sample>, List<Sample>> {
        val inputStream = javaClass.getResourceAsStream("/spam_samples_round3.tsv")
        assertNotNull("spam_samples_round3.tsv must exist in test resources", inputStream)

        val reader = InputStreamReader(inputStream!!, StandardCharsets.UTF_8)
        val lines = reader.readLines().drop(1).filter { it.isNotBlank() }

        val spamList = mutableListOf<Sample>()
        val hamList = mutableListOf<Sample>()

        for (line in lines) {
            val parts = line.split("\t")
            if (parts.size < 3) continue
            val sample = Sample(
                label = parts[2].trim().uppercase(Locale.ROOT),
                address = parts[0].trim(),
                body = parts[1].trim()
            )
            if (sample.label == "SPAM") {
                spamList.add(sample)
            } else if (sample.label == "HAM") {
                hamList.add(sample)
            }
        }
        return Pair(spamList, hamList)
    }

    @Test
    fun testSpamScorerOnRound3Dataset() {
        val (round3Spam, round3Ham) = loadRound3Samples()

        println("==================================================")
        println("  ROUND 3 WINDFALL & CONFOUNDING SAMPLES")
        println("==================================================")

        var spamAt60OrMore = 0
        for (sample in round3Spam) {
            val res = SpamScorer.score(sample.address, sample.body)
            if (res.score >= SpamScorer.THRESHOLD_SPAM) {
                spamAt60OrMore++
            }
            println("[SPAM | Score: ${res.score}] ${sample.address}: ${sample.body}")
            println("  Reasons: ${res.reasons.joinToString("; ")}")
        }

        var hamAt60OrMore = 0
        for (sample in round3Ham) {
            val res = SpamScorer.score(sample.address, sample.body)
            if (res.score >= SpamScorer.THRESHOLD_SPAM) {
                hamAt60OrMore++
            }
            println("[HAM  | Score: ${res.score}] ${sample.address}: ${sample.body}")
            println("  Reasons: ${res.reasons.joinToString("; ")}")
        }

        println("--- SUMMARY ---")
        println("Windfall Spam scoring >= 60: $spamAt60OrMore / ${round3Spam.size}")
        println("Legitimate Ham scoring >= 60: $hamAt60OrMore / ${round3Ham.size}")
        println("==================================================")

        assertEquals("All windfall spam must score >= 60", round3Spam.size, spamAt60OrMore)
        assertEquals("Zero legitimate ham must score >= 60", 0, hamAt60OrMore)
    }

    @Test
    fun testEmptyMessage() {
        val result = SpamScorer.score("+923001234567", "")
        assertEquals(0, result.score)
        assertEquals(false, result.isSpam)
        assertTrue(result.reasons.isEmpty())
    }

    @Test
    fun testBlankMessage() {
        val result = SpamScorer.score("+923001234567", "    ")
        assertEquals(0, result.score)
        assertEquals(false, result.isSpam)
        assertTrue(result.reasons.isEmpty())
    }

    @Test
    fun testLegitimateBoundaryWordsScoreBelow30() {
        val boundarySentences = listOf(
            "+923001112233" to "Meet me near the botanical garden at 5 PM for evening tea.",
            "+923012223344" to "Your hidden gift is kept inside the desk drawer at home.",
            "+923023334455" to "Every student must carry their university ID card to the exam hall.",
            "+923034445566" to "You now have access to the library portal for downloading research papers.",
            "+923045556677" to "Please check the bank account statement before filing the annual report.",
            "+923056667788" to "Here are the HBL branch details and office timings for tomorrow's visit."
        )

        for ((address, body) in boundarySentences) {
            val res = SpamScorer.score(address, body)
            assertTrue(
                "Legitimate boundary sentence scored ${res.score} (>= 30): '$body' | Reasons: ${res.reasons}",
                res.score < SpamScorer.THRESHOLD_SUSPICIOUS
            )
        }
    }

    companion object {
        const val STRATIFIED_SPLIT_SEED = 42L
    }

    data class PhishingSample(
        val address: String,
        val body: String,
        val label: String,
        val category: String,
    )

    data class SplitResult(
        val tuning: List<PhishingSample>,
        val heldOut: List<PhishingSample>,
    )

    private fun loadPhishing1000Samples(): List<PhishingSample> {
        val inputStream = javaClass.getResourceAsStream("/phishing_dataset_1000.tsv")
            ?: return emptyList()

        val reader = InputStreamReader(inputStream, StandardCharsets.UTF_8)
        val lines = reader.readLines().drop(1).filter { it.isNotBlank() }
        val list = mutableListOf<PhishingSample>()

        for (line in lines) {
            val parts = line.split("\t")
            if (parts.size >= 4) {
                list.add(
                    PhishingSample(
                        address = parts[0].trim(),
                        body = parts[1].trim(),
                        label = parts[2].trim().lowercase(Locale.ROOT),
                        category = parts[3].trim()
                    )
                )
            }
        }
        return list
    }

    private fun splitStratified5050(samples: List<PhishingSample>): SplitResult {
        val rng = java.util.Random(STRATIFIED_SPLIT_SEED)
        val tuning = mutableListOf<PhishingSample>()
        val heldOut = mutableListOf<PhishingSample>()

        val byCat = samples.groupBy { it.category }
        for (category in byCat.keys.sorted()) {
            val list = byCat[category]!!.toMutableList()
            for (i in list.size - 1 downTo 1) {
                val j = rng.nextInt(i + 1)
                val temp = list[i]
                list[i] = list[j]
                list[j] = temp
            }
            val half = list.size / 2
            tuning.addAll(list.take(half))
            heldOut.addAll(list.drop(half))
        }
        return SplitResult(tuning, heldOut)
    }

    data class PhishingEvalMetrics(
        val name: String,
        val total: Int,
        val totalSpam: Int,
        val totalHam: Int,
        val spamCaught60: Int,
        val spamCaught30: Int,
        val hamFlagged60: Int,
        val hamFlagged30: Int,
        val categorySpamCaught60: Map<String, Pair<Int, Int>>,
    )

    private fun evaluatePhishingSubset(name: String, subset: List<PhishingSample>): PhishingEvalMetrics {
        var spamCaught60 = 0
        var spamCaught30 = 0
        var hamFlagged60 = 0
        var hamFlagged30 = 0
        var totalSpam = 0
        var totalHam = 0

        val catSpamTotal = mutableMapOf<String, Int>()
        val catSpamCaught = mutableMapOf<String, Int>()

        for (sample in subset) {
            val res = SpamScorer.score(sample.address, sample.body)
            val isSpam = sample.label == "spam"
            if (isSpam) {
                totalSpam++
                catSpamTotal[sample.category] = (catSpamTotal[sample.category] ?: 0) + 1
                if (res.score >= SpamScorer.THRESHOLD_SPAM) {
                    spamCaught60++
                    catSpamCaught[sample.category] = (catSpamCaught[sample.category] ?: 0) + 1
                }
                if (res.score >= SpamScorer.THRESHOLD_SUSPICIOUS) {
                    spamCaught30++
                }
            } else {
                totalHam++
                if (res.score >= SpamScorer.THRESHOLD_SPAM) {
                    hamFlagged60++
                }
                if (res.score >= SpamScorer.THRESHOLD_SUSPICIOUS) {
                    hamFlagged30++
                }
            }
        }

        val catMap = mutableMapOf<String, Pair<Int, Int>>()
        for (cat in catSpamTotal.keys) {
            catMap[cat] = Pair(catSpamCaught[cat] ?: 0, catSpamTotal[cat] ?: 0)
        }

        return PhishingEvalMetrics(
            name = name,
            total = subset.size,
            totalSpam = totalSpam,
            totalHam = totalHam,
            spamCaught60 = spamCaught60,
            spamCaught30 = spamCaught30,
            hamFlagged60 = hamFlagged60,
            hamFlagged30 = hamFlagged30,
            categorySpamCaught60 = catMap
        )
    }

    private fun printMetrics(m: PhishingEvalMetrics) {
        val recall = if (m.totalSpam > 0) (m.spamCaught60.toDouble() / m.totalSpam) * 100.0 else 0.0
        val precision = if (m.spamCaught60 + m.hamFlagged60 > 0) {
            (m.spamCaught60.toDouble() / (m.spamCaught60 + m.hamFlagged60)) * 100.0
        } else 100.0
        println("--- ${m.name} ---")
        println("Total: ${m.total} (Spam: ${m.totalSpam}, Ham: ${m.totalHam})")
        println("Spam caught at 60 (x/y): ${m.spamCaught60}/${m.totalSpam} (${"%.2f".format(Locale.ROOT, recall)}%)")
        println("Legitimate flagged at 60 (x/y): ${m.hamFlagged60}/${m.totalHam}")
        println("Spam at 30 or higher (x/y): ${m.spamCaught30}/${m.totalSpam}")
        println("Precision: ${"%.2f".format(Locale.ROOT, precision)}%")
        println("Category Spam Recall (>= 60):")
        for ((cat, counts) in m.categorySpamCaught60.entries.sortedByDescending { it.value.second }) {
            val pct = if (counts.second > 0) (counts.first.toDouble() / counts.second) * 100.0 else 0.0
            println("  $cat: ${counts.first}/${counts.second} (${"%.1f".format(Locale.ROOT, pct)}%)")
        }
    }

    private fun printTuningMisses(tuning: List<PhishingSample>) {
        println("\n--- TUNING HALF MISSED SPAM SAMPLES (< 60) ---")
        val missed = tuning.filter { it.label == "spam" }
            .map { it to SpamScorer.score(it.address, it.body) }
            .filter { it.second.score < SpamScorer.THRESHOLD_SPAM }

        for ((index, pair) in missed.take(10).withIndex()) {
            val (sample, res) = pair
            println("[Tuning Miss #${index + 1}] Score: ${res.score} | Cat: ${sample.category}")
            println("  Text: ${sample.body}")
            println("  Reasons: ${res.reasons.joinToString("; ")}")
        }
        println("Total Tuning Misses: ${missed.size}")
    }

    private fun printHighestScoringHam(samples: List<PhishingSample>) {
        val highestScoringHam = samples.filter { it.label == "ham" }
            .map { it to SpamScorer.score(it.address, it.body) }
            .sortedByDescending { it.second.score }
            .take(5)

        println("\n--- TOP HIGHEST-SCORING LEGITIMATE MESSAGES ---")
        for ((sample, res) in highestScoringHam) {
            println("Score: ${res.score} | Cat: ${sample.category} | From: ${sample.address}")
            println("  Text: ${sample.body}")
            println("  Reasons: ${res.reasons.joinToString("; ")}")
        }
    }

    @Test
    fun testSpamScorerOn1000PhishingDataset() {
        val samples = loadPhishing1000Samples()
        if (samples.isEmpty()) {
            println("Skipping testSpamScorerOn1000PhishingDataset: phishing_dataset_1000.tsv not present")
            return
        }
        assertTrue("Dataset must contain 1000 samples", samples.size >= 1000)

        val split = splitStratified5050(samples)

        println("==================================================")
        println("  1,000 PHISHING DATASET EVALUATION")
        println("  Deterministic Stratified Split Seed: $STRATIFIED_SPLIT_SEED")
        println("==================================================")

        val fullMetrics = evaluatePhishingSubset("FULL SET (1,000)", samples)
        printMetrics(fullMetrics)

        val tuningMetrics = evaluatePhishingSubset("TUNING HALF (50%)", split.tuning)
        printMetrics(tuningMetrics)

        val heldOutMetrics = evaluatePhishingSubset("HELD-OUT HALF (50% - AGGREGATES ONLY)", split.heldOut)
        printMetrics(heldOutMetrics)

        printTuningMisses(split.tuning)
        printHighestScoringHam(samples)
        println("==================================================")

        // Hard constraints: zero legitimate messages at 60 or more
        assertEquals("Full set must have 0 false positives", 0, fullMetrics.hamFlagged60)
        assertEquals("Tuning half must have 0 false positives", 0, tuningMetrics.hamFlagged60)
        assertEquals("Held-out half must have 0 false positives", 0, heldOutMetrics.hamFlagged60)
    }
}
