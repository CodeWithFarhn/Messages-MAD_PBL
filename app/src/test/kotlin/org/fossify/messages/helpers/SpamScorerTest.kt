package org.fossify.messages.helpers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

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
        val missedSpam: List<Pair<Sample, SpamScorer.SpamResult>>,
        val wronglyFlaggedHam: List<Pair<Sample, SpamScorer.SpamResult>>,
        val suspiciousHamList: List<Pair<Sample, SpamScorer.SpamResult>>,
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

    private fun evaluate(spamSet: List<Sample>, hamSet: List<Sample>): EvaluationResult {
        var tp = 0
        var fn = 0
        var tn = 0
        var fp = 0
        var suspiciousHam = 0

        val missedSpam = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()
        val wronglyFlaggedHam = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()
        val suspiciousHamList = mutableListOf<Pair<Sample, SpamScorer.SpamResult>>()

        for (sample in spamSet) {
            val result = SpamScorer.score(sample.address, sample.body)
            if (result.isSpam) {
                tp++
            } else {
                fn++
                missedSpam.add(Pair(sample, result))
            }
        }

        for (sample in hamSet) {
            val result = SpamScorer.score(sample.address, sample.body)
            if (result.isSpam) {
                fp++
                wronglyFlaggedHam.add(Pair(sample, result))
            } else {
                tn++
                if (result.score in SpamScorer.THRESHOLD_SUSPICIOUS until SpamScorer.THRESHOLD_SPAM) {
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
            missedSpam = missedSpam,
            wronglyFlaggedHam = wronglyFlaggedHam,
            suspiciousHamList = suspiciousHamList
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
        println("Spam Recall: %.1f%%".format(res.recall))
        println("Precision: %.1f%%".format(res.precision))
        println("Wrongly Flagged Legitimate (score >= 60): ${res.falsePositives}")
        println("Suspicious Legitimate (score 30..59): ${res.suspiciousHam}")

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

    @Test
    fun testSpamScorerAccuracyOnTuningAndHeldOutSets() {
        val (allSpam, allHam, borderline) = loadSamples()

        assertTrue("Dataset must contain at least 120 total samples", (allSpam.size + allHam.size) >= 120)

        // 60/40 split
        val spamTuningCount = (allSpam.size * 0.6).toInt()
        val hamTuningCount = (allHam.size * 0.6).toInt()

        val spamTuning = allSpam.take(spamTuningCount)
        val spamHeldOut = allSpam.drop(spamTuningCount)

        val hamTuning = allHam.take(hamTuningCount)
        val hamHeldOut = allHam.drop(hamTuningCount)

        // Evaluate Tuning Set
        val tuningResult = evaluate(spamTuning, hamTuning)
        printReport("TUNING SET EVALUATION (60% split)", tuningResult)

        // Evaluate Held-out Set
        val heldOutResult = evaluate(spamHeldOut, hamHeldOut)
        printReport("HELD-OUT SET EVALUATION (40% split)", heldOutResult)

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

        // Assertions
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
}

