package org.fossify.messages.helpers

import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * Pure Kotlin spam scorer for SMS messages.
 * Evaluates message body and sender address using heuristics, keyword dictionaries,
 * and pattern reductions.
 *
 * Designed to run without Android dependencies so that it can be executed in pure JVM unit tests.
 */
object SpamScorer {

    const val THRESHOLD_SPAM = 60
    const val THRESHOLD_SUSPICIOUS = 30

    // Weights
    const val WEIGHT_LINK = 25
    const val WEIGHT_SHORT_URL = 10
    const val WEIGHT_SPAM_KEYWORD = 15
    const val MAX_SPAM_KEYWORD_SCORE = 45
    const val WEIGHT_MONEY_PRIZE = 15
    const val WEIGHT_URGENCY = 10
    const val WEIGHT_CREDENTIAL_REQUEST = 30
    const val WEIGHT_SENDER_SHAPE = 10
    const val WEIGHT_CAPITALS_EXCLAMATION = 10

    // Reductions
    const val REDUCTION_OTP = 30
    const val REDUCTION_TRANSACTION = 20

    // Thresholds & Constants
    private const val MIN_LETTERS_FOR_CAPS = 10
    private const val MAX_CAPITAL_RATIO = 0.40
    private const val MIN_EXCLAMATION_COUNT = 3
    private const val MIN_SHORTCODE_LENGTH = 3
    private const val MAX_SHORTCODE_LENGTH = 6
    private const val MAX_SCORE = 100

    data class SpamResult(
        val score: Int,
        val reasons: List<String>,
        val isSpam: Boolean,
    )

    private val URL_REGEX = Regex(
        "(?:https?://|www\\.)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?::\\d+)?(?:/[^\\s]*)?",
        RegexOption.IGNORE_CASE
    )

    private val IP_URL_REGEX = Regex(
        "\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?(?:/[^\\s]*)?\\b"
    )

    // Allowed top-level domains for bare domain matching (e.g. claim-now.xyz)
    private val ALLOWED_TLDS = setOf(
        "com", "org", "net", "edu", "gov", "pk", "io", "info", "biz",
        "xyz", "top", "me", "live", "co", "app", "dev", "site", "online",
        "store", "club", "vip", "link", "click", "space", "tech", "pro",
        "buzz", "icu", "shop", "cash", "loan"
    )

    private val BARE_DOMAIN_REGEX = Regex(
        "\\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.([a-zA-Z]{2,10})(?::\\d+)?(?:/[^\\s]*)?\\b"
    )

    private val SHORT_URL_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "goo.gl", "cutt.ly", "shorturl.at", "rb.gy", "trib.al",
        "v.gd", "tiny.cc", "bit.do"
    )

    // Credential & sensitive info requests
    private val CREDENTIAL_PATTERNS = listOf(
        Regex("\\b(?:pin|cnic|password|passcode|cvv|atm\\s*pin|id\\s*card\\s*(?:no|number)|card\\s*expiry)\\b"),
        Regex(
            "(?:send|share|forward|verify|provide|enter|submit)\\s+(?:your|ur)?\\s*" +
                "(?:pin|cnic|password|otp|code|account\\s*details)"
        ),
        Regex("(?:apna|apni)\\s+(?:pin|cnic|password|otp|code)\\s+(?:bhej|send|share|batain|likhain)"),
        Regex("cnic\\s*(?:number|no)?\\s*(?:send|bhejo|bhejen|karain)")
    )

    // Money or prize language
    private val PRIZE_PATTERNS = listOf(
        Regex("\\b(?:winner|congratulations|prize|jackpot|lucky\\s*draw|qurandazi|lottery)\\b"),
        Regex(
            "(?:you\\s*(?:have)?\\s*won|aap\\s*jeet\\s*chuke|inam\\s*nikla|" +
                "lottery\\s*nikli|claim\\s*(?:your)?\\s*prize)"
        ),
        Regex("(?:rs\\.?|pkr)\\s*[0-9,]+\\s*(?:inam|prize|cash|jeet)"),
        Regex("(?:mubarak\\s*ho|mubarak).*inam")
    )

    // Urgency language
    private val URGENCY_PATTERNS = listOf(
        Regex("\\b(?:urgent|immediately|act\\s*now|action\\s*required|last\\s*chance|final\\s*notice|deactivation)\\b"),
        Regex("(?:within\\s*24\\s*hours|account\\s*(?:will\\s*be|is)\\s*suspended|sim\\s*(?:band|block))"),
        Regex("(?:block\\s*hone\\s*se\\s*bach(?:ayein|ain)|fauran\\s*(?:rabta|call|update))"),
        Regex("(?:service\\s*(?:termination|interruption)|immediate\\s*verification)")
    )

    // English spam keyword phrases
    private val ENGLISH_SPAM_KEYWORDS = listOf(
        Regex("claim\\s*(?:your)?\\s*free"),
        Regex("exclusive\\s*deal"),
        Regex("guaranteed\\s*(?:return|profit|income)"),
        Regex("click\\s*(?:the\\s*link\\s*)?to\\s*claim"),
        Regex("pre-?approved\\s*(?:loan|credit|cash)"),
        Regex("earn\\s*(?:\\$|rs\\.?|pkr)?\\s*[0-9,]+\\s*(?:daily|weekly|from\\s*home)"),
        Regex("work\\s*from\\s*home\\s*(?:earn|job)"),
        Regex("no\\s*investment\\s*needed"),
        Regex("instant\\s*(?:cash|loan)\\s*approval"),
        Regex("double\\s*your\\s*money"),
        Regex("100%\\s*(?:free|guaranteed)")
    )

    // Roman Urdu & Local scam keyword phrases
    // Note: Brand/program names (BISP, Ehsaas, 8171) only match when combined with action/claim cues
    private val ROMAN_URDU_SPAM_KEYWORDS = listOf(
        Regex(
            "(?:bisp|benazir|ehsaas|8171).*" +
                "(?:balance|waseela|rashan|claim|fauran|rabta|paise|kist|mil\\s*gaye|jaanch)"
        ),
        Regex("(?:lottery|inam)\\s*(?:nikli|nikla|mubarak|lagi)"),
        Regex("qurandazi\\s*mein\\s*(?:naam|inam)"),
        Regex("(?:sim|account)\\s*(?:band|block)\\s*(?:kar\\s*diya|hone\\s*se\\s*bach)"),
        Regex("(?:jazzcash|easypaisa).*(?:block|suspended|lottery|inam|waseela)"),
        Regex("ghar\\s*baith(?:ay|e)\\s*(?:paise\\s*)?kamain"),
        Regex("online\\s*(?:karobar|investment|kamai)"),
        Regex("bina\\s*(?:kisi\\s*)?investment"),
        Regex("fauran\\s*is\\s*number\\s*par\\s*rabta")
    )

    // Legitimate OTP / 2FA patterns
    private val OTP_PATTERNS = listOf(
        Regex("\\b(?:verification|security|login|auth(?:entication)?|confirmation|access)\\s*code\\b"),
        Regex("\\b(?:one[- ]time\\s*(?:passcode|password)|otp)\\b"),
        Regex("(?:your|is\\s*your)\\s*(?:otp|code|password)\\s*(?:is|:)\\s*[0-9]{4,8}"),
        Regex("code\\s*(?:is|:)\\s*[0-9]{4,8}"),
        Regex("\\bdo\\s*not\\s*share\\s*(?:this|your)?\\s*(?:code|otp)\\b"),
        Regex("(?:kisi\\s*ko\\s*na\\s*batain|kisi\\s*se\\s*share\\s*na\\s*karain)")
    )

    // Legitimate banking transaction alert patterns
    private val TRANSACTION_PATTERNS = listOf(
        Regex("\\b(?:debited|credited)\\s*(?:by|with|for|to)?\\s*(?:rs\\.?|pkr|inr|usd|\\$)?\\s*[0-9,]+"),
        Regex("\\b(?:tran?s?action|txn)\\s*(?:alert|successful|id|ref|declined)\\b"),
        Regex("(?:acct?|a/c)\\s*(?:no\\.?|ending|#)?\\s*[x*]*[0-9]{3,4}"),
        Regex("\\b(?:avl|available)\\s*(?:bal|balance)\\b"),
        Regex("(?:paid\\s*to|withdrawn\\s*(?:from|at)|bill\\s*payment\\s*of)"),
        Regex("(?:atm\\s*w/d|pos\\s*txn|fund\\s*transfer)")
    )

    /**
     * Scores an incoming SMS message.
     *
     * @param address The sender address (phone number, short code, or alphanumeric name).
     * @param body The text content of the message.
     * @return SpamResult containing numeric score (0..100), human-readable reasons, and isSpam boolean.
     */
    fun score(address: String, body: String): SpamResult {
        if (body.isBlank()) {
            return SpamResult(0, emptyList(), false)
        }

        var score = 0
        val reasons = mutableListOf<String>()

        // 1. Raw body formatting cues
        val formattingReason = checkFormatting(body)
        if (formattingReason != null) {
            score += WEIGHT_CAPITALS_EXCLAMATION
            reasons.add(formattingReason)
        }

        // 2. Normalized body
        val normalizedBody = body.lowercase(Locale.ROOT).replace(Regex("\\s+"), " ")

        // 3. Link Detection
        val (linkScore, linkReasons, hasLink) = evaluateLinks(normalizedBody)
        score += linkScore
        reasons.addAll(linkReasons)

        // 4. Content Signals
        val hasCredential = anyPatternMatches(normalizedBody, CREDENTIAL_PATTERNS)
        if (hasCredential) {
            score += WEIGHT_CREDENTIAL_REQUEST
            reasons.add("Sensitive credential request (+$WEIGHT_CREDENTIAL_REQUEST)")
        }

        val hasPrize = anyPatternMatches(normalizedBody, PRIZE_PATTERNS)
        if (hasPrize) {
            score += WEIGHT_MONEY_PRIZE
            reasons.add("Prize / lottery / cash language (+$WEIGHT_MONEY_PRIZE)")
        }

        if (anyPatternMatches(normalizedBody, URGENCY_PATTERNS)) {
            score += WEIGHT_URGENCY
            reasons.add("Urgent action / suspension threat (+$WEIGHT_URGENCY)")
        }

        // 5. Spam keywords
        val keywordScore = evaluateKeywords(normalizedBody, reasons)
        score += keywordScore

        // 6. Reductions & Legitimate Patterns
        val isOtp = anyPatternMatches(normalizedBody, OTP_PATTERNS)
        val isTxn = anyPatternMatches(normalizedBody, TRANSACTION_PATTERNS)
        val isStrongAttack = hasCredential || (hasPrize && hasLink)

        if (!isStrongAttack) {
            score -= applyReductions(isOtp, isTxn, reasons)
        }

        // 7. Sender Shape
        if (isSuspiciousSender(address, isOtp, isTxn)) {
            score += WEIGHT_SENDER_SHAPE
            reasons.add("Alphanumeric or shortcode sender (+$WEIGHT_SENDER_SHAPE)")
        }

        val clampedScore = max(0, min(MAX_SCORE, score))
        return SpamResult(clampedScore, reasons, clampedScore >= THRESHOLD_SPAM)
    }

    private fun checkFormatting(body: String): String? {
        val rawLetters = body.filter { it.isLetter() }
        val uppercaseCount = rawLetters.count { it.isUpperCase() }
        val exclamationCount = body.count { it == '!' }

        val excessiveCaps = rawLetters.length >= MIN_LETTERS_FOR_CAPS &&
            (uppercaseCount.toDouble() / rawLetters.length) > MAX_CAPITAL_RATIO
        val excessiveExclamations = exclamationCount >= MIN_EXCLAMATION_COUNT

        return when {
            excessiveCaps && excessiveExclamations ->
                "Formatting: excessive capitals and exclamation marks (+$WEIGHT_CAPITALS_EXCLAMATION)"
            excessiveCaps ->
                "Formatting: excessive capital letters (+$WEIGHT_CAPITALS_EXCLAMATION)"
            excessiveExclamations ->
                "Formatting: multiple exclamation marks (+$WEIGHT_CAPITALS_EXCLAMATION)"
            else -> null
        }
    }

    private data class LinkEvaluation(
        val score: Int,
        val reasons: List<String>,
        val hasLink: Boolean,
    )

    private fun evaluateLinks(normalizedBody: String): LinkEvaluation {
        val hasExplicitLink = URL_REGEX.containsMatchIn(normalizedBody) ||
            IP_URL_REGEX.containsMatchIn(normalizedBody)
        val hasBareDomain = if (!hasExplicitLink) hasAllowedBareDomain(normalizedBody) else false
        val hasLink = hasExplicitLink || hasBareDomain

        if (!hasLink) {
            return LinkEvaluation(0, emptyList(), false)
        }

        var linkScore = WEIGHT_LINK
        val reasons = mutableListOf("Link detected (+$WEIGHT_LINK)")

        val hasShortUrl = SHORT_URL_DOMAINS.any { normalizedBody.contains(it) }
        if (hasShortUrl) {
            linkScore += WEIGHT_SHORT_URL
            reasons.add("Shortened URL service (+$WEIGHT_SHORT_URL)")
        }

        return LinkEvaluation(linkScore, reasons, true)
    }

    private fun hasAllowedBareDomain(normalizedBody: String): Boolean {
        return BARE_DOMAIN_REGEX.findAll(normalizedBody).any { match ->
            val tld = match.groupValues.getOrNull(1)?.lowercase(Locale.ROOT)
            tld != null && ALLOWED_TLDS.contains(tld)
        }
    }

    private fun anyPatternMatches(text: String, patterns: List<Regex>): Boolean {
        return patterns.any { it.containsMatchIn(text) }
    }

    private fun evaluateKeywords(normalizedBody: String, reasons: MutableList<String>): Int {
        val enCount = ENGLISH_SPAM_KEYWORDS.count { it.containsMatchIn(normalizedBody) }
        val urCount = ROMAN_URDU_SPAM_KEYWORDS.count { it.containsMatchIn(normalizedBody) }
        val total = enCount + urCount

        if (total > 0) {
            val keywordScore = min(total * WEIGHT_SPAM_KEYWORD, MAX_SPAM_KEYWORD_SCORE)
            reasons.add("Spam keywords matched ($total match(es), +$keywordScore)")
            return keywordScore
        }
        return 0
    }

    private fun applyReductions(isOtp: Boolean, isTxn: Boolean, reasons: MutableList<String>): Int {
        var reduction = 0
        if (isOtp) {
            reduction += REDUCTION_OTP
            reasons.add("Legitimate OTP / verification code pattern (-$REDUCTION_OTP)")
        }
        if (isTxn) {
            reduction += REDUCTION_TRANSACTION
            reasons.add("Legitimate transaction / balance alert pattern (-$REDUCTION_TRANSACTION)")
        }
        return reduction
    }

    private fun isSuspiciousSender(address: String, isOtp: Boolean, isTxn: Boolean): Boolean {
        if (isOtp || isTxn) return false
        val clean = address.trim().removePrefix("+")
        if (clean.isEmpty()) return false
        val isAlphanumeric = clean.any { it.isLetter() }
        val isShortcode = clean.all { it.isDigit() } && clean.length in MIN_SHORTCODE_LENGTH..MAX_SHORTCODE_LENGTH
        return isAlphanumeric || isShortcode
    }
}
