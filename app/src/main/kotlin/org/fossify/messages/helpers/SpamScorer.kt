package org.fossify.messages.helpers

import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * Pure Kotlin spam scorer for SMS messages.
 * Evaluates message body and sender address using heuristics, keyword dictionaries,
 * impersonation detection, and pattern reductions.
 *
 * Designed to run without Android dependencies so that it can be executed in pure JVM unit tests.
 */
object SpamScorer {

    const val THRESHOLD_SPAM = 60
    const val THRESHOLD_SUSPICIOUS = 30

    // Tuned Weights
    const val WEIGHT_LINK = 25
    const val WEIGHT_SHORT_URL = 15
    const val WEIGHT_SPAM_KEYWORD = 20
    const val MAX_SPAM_KEYWORD_SCORE = 50
    const val WEIGHT_MONEY_PRIZE = 20
    const val WEIGHT_URGENCY = 20
    const val WEIGHT_CREDENTIAL_REQUEST = 40
    const val WEIGHT_IMPERSONATION = 30
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
    private const val MIN_MOBILE_NUMBER_LENGTH = 10
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

    // Credential & sensitive info requests (both English and Roman Urdu noun-verb orders with word boundaries)
    private val CREDENTIAL_PATTERNS = listOf(
        Regex(
            "(?<!do not |never |don't |na |kisi se )\\b" +
                "(?:send|share|forward|provide|enter|submit|batain|bhej(?:o|en|ain)?|likhain)\\b\\s+" +
                "(?:your|ur|apna|apni)?\\s*\\b(?:atm|pin|cnic|password|cvv|code|passcode)\\b"
        ),
        Regex(
            "(?<!do not |never |don't |na |kisi se )" +
                "(?:apna|apni|your|ur)?\\s*\\b(?:atm|pin|cnic|password|cvv|id card number|secret pin)\\b\\s*" +
                ".*\\b(?:send|bhej(?:o|en|ain)?|share|batain|karain|verify|provide|likhain)\\b"
        ),
        Regex("(?<!do not |never |don't |na |kisi se )\\b(?:your|ur|apna|apni|secret)\\s+pin\\b"),
        Regex("cnic.*\\b(?:send|bhej(?:o|en|ain)?|share|batain)\\s*karain\\b"),
        Regex("\\b(?:atm\\s*pin|cvv|card\\s*expiry)\\b.*\\b(?:send|bhej|share|batain|verify)\\b"),
        Regex("\\b(?:verify|update)\\b\\s+(?:your|ur)?\\s*\\b(?:identity|cnic|atm|pin|cvv)\\b")
    )

    // Impersonation: Institutions/brands combined with personal mobile senders
    private val INSTITUTION_PATTERNS = listOf(
        Regex("\\b(?:bisp|benazir|ehsaas|8171|jazzcash|easypaisa|pta|fbr|nadra)\\b"),
        Regex("\\b(?:hbl|meezan|alfalah|ubl|mcb|allied|standard\\s*chartered|faysal|bank)\\b"),
        Regex("\\b(?:tcs|dhl|leopard|daraz|bykea|careem|uber|foodpanda)\\b"),
        Regex("\\b(?:jazz|telenor|zong|ufone)\\b"),
        Regex("(?:بے نظیر|8171|احساس|بینک)")
    )

    // Impersonation action triggers
    private val ACTION_PATTERNS = listOf(
        Regex(
            "\\b(?:call|contact|rabta|claim|wasool|send|" +
                "bhej(?:o|en|ain)?|share|batain|verify|tasdeeq|click|link|update)\\b"
        ),
        Regex("https?://"),
        Regex("(?:رابطہ|کال|دعویٰ|حاصل)")
    )

    // Money or prize language (strictly requires prize context; plain bills/fares do not match)
    private val PRIZE_PATTERNS = listOf(
        Regex(
            "\\b(?:winner|congratulations|congrats|mubarak(?:\\s*ho)?|" +
                "prize|jackpot|lucky\\s*draw|qurandazi|lottery|gold\\s*bar|honda\\s*(?:125|city)?|\\bcar\\b)\\b"
        ),
        Regex(
            "(?:you\\s*(?:have)?\\s*won|aap\\s*jeet\\s*chuke|\\binam\\b|" +
                "\\bwazeefa\\b|cash\\s*reward|reward|kist\\s*(?:wasool|jari|mil|aa\\s*gayi))"
        ),
        Regex("(?:rs\\.?|pkr|\\$)\\s*[0-9,]+\\s*(?:inam|prize|cash|jeet|wazeefa|kist|reward|bonus)"),
        Regex("(?:received|withdraw).*(?:btc|bitcoin|crypto|wallet|\\$[0-9,]+)"),
        Regex("(?:مبارک|انعام|لاٹری|قرعہ اندازی|وظیفہ|دعویٰ)")
    )

    // Urgency language
    private val URGENCY_PATTERNS = listOf(
        Regex(
            "\\b(?:urgent|immediately|act\\s*now|action\\s*required|" +
                "last\\s*chance|final\\s*notice|deactivation|warning|notice)\\b"
        ),
        Regex(
            "(?:within\\s*\\d+\\s*hours|24\\s*hours|" +
                "account\\s*(?:will\\s*be|is)\\s*suspended|sim\\s*block)"
        ),
        Regex(
            "(?:block\\s*hone\\s*se\\s*bach(?:ayein|ain|ne)|" +
                "fauran|abhi|arrest|legal\\s*action|avoid\\s*(?:permanent)?\\s*closure)"
        ),
        Regex("(?:service\\s*(?:termination|interruption)|immediate\\s*verification)"),
        Regex("(?:فوراً|بند ہو|بلاک)")
    )

    // English spam keyword phrases
    private val ENGLISH_SPAM_KEYWORDS = listOf(
        Regex("claim\\s*(?:your)?\\s*free"),
        Regex("exclusive\\s*(?:deal|offer)"),
        Regex("guaranteed\\s*(?:return|profit|income|approval)"),
        Regex("click\\s*(?:the\\s*link\\s*)?to\\s*claim"),
        Regex("(?:instant|urgent|easy|fast|pre-?approved)\\s*(?:cash|loan)"),
        Regex("earn\\s*(?:\\$|rs\\.?|pkr)?\\s*[0-9,]+\\s*(?:daily|weekly|from\\s*home)"),
        Regex("work\\s*from\\s*home"),
        Regex("no\\s*(?:investment|experience|guarantor)\\s*needed"),
        Regex("double\\s*your\\s*(?:money|income)"),
        Regex("(?:unpaid|due)\\s*invoice.*settle"),
        Regex(
            "(?:security\\s*breach|unusual\\s*sign-in|account\\s*locked|" +
                "unauthorized|verification\\s*pending).*verify"
        ),
        Regex("pay\\s*(?:release|customs|delivery|transfer)?\\s*fee"),
        Regex("limited\\s*(?:vouchers|time|slots)"),
        Regex("(?:zero|0%|no)\\s*(?:percent|%|interest|mark-?up)")
    )

    // Roman Urdu & Local scam keyword phrases
    // Note: Brand/program names (BISP, Ehsaas, 8171, PTA) only match when combined with action/claim cues
    private val ROMAN_URDU_SPAM_KEYWORDS = listOf(
        Regex(
            "(?:bisp|benazir|ehsaas|8171).*" +
                "(?:balance|wazeefa|rashan|claim|fauran|rabta|paise|kist|" +
                "mil\\s*gaye|jaanch|kafalat|taleem|verify|relief)"
        ),
        Regex("(?:lottery|inam|prize).*(?:nikli|nikla|lagi|mubarak|jeet|claim|wasool|lene)"),
        Regex("jeeto\\s*pakistan"),
        Regex("qurandazi.*(?:naam|inam|result|cash)"),
        Regex("(?:sim|account|number).*(?:band|block|suspend|deactivat)"),
        Regex("(?:jazzcash|easypaisa).*(?:block|suspend|lottery|inam|waseela|error|unblock)"),
        Regex("(?:pta|fbr).*(?:warning|alert|rule|verification|tax|illegal|terrorist)"),
        Regex("ghar\\s*baith(?:ay|e).*kamain"),
        Regex("online\\s*(?:karobar|investment|kamai)"),
        Regex("bina\\s*(?:kisi\\s*)?investment"),
        Regex("(?:call|rabta|contact)\\s*(?:karain|karein|farmain|kijiye).*03[0-9]{9}"),
        Regex("(?:بے نظیر|8171|احساس|وظیفہ|انعام|لاٹری|قرعہ اندازی|دعویٰ)")
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

        // 5. Impersonation Signal (+30)
        if (isImpersonatingBrandFromMobile(address, normalizedBody)) {
            score += WEIGHT_IMPERSONATION
            reasons.add("Institution / brand impersonation from mobile number (+$WEIGHT_IMPERSONATION)")
        }

        // 6. Spam keywords
        val keywordScore = evaluateKeywords(normalizedBody, reasons)
        score += keywordScore

        // 7. Reductions & Legitimate Patterns
        val isOtp = anyPatternMatches(normalizedBody, OTP_PATTERNS)
        val isTxn = anyPatternMatches(normalizedBody, TRANSACTION_PATTERNS)
        val isStrongAttack = hasCredential || (hasPrize && hasLink)

        if (!isStrongAttack) {
            score -= applyReductions(isOtp, isTxn, reasons)
        }

        // 8. Sender Shape
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

    private fun isImpersonatingBrandFromMobile(address: String, normalizedBody: String): Boolean {
        val clean = address.trim().replace(Regex("[\\s-+()]"), "")
        val isMobile = clean.length >= MIN_MOBILE_NUMBER_LENGTH && clean.all { it.isDigit() }
        if (!isMobile) return false

        val namesInstitution = INSTITUTION_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        val hasAction = ACTION_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        return namesInstitution && hasAction
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
