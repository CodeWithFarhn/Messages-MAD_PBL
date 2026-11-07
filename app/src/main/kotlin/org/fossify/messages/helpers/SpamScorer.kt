package org.fossify.messages.helpers

import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * Pure Kotlin spam scorer for SMS messages.
 * Evaluates message body and sender address using heuristics, keyword dictionaries,
 * brand impersonation, advance-fee detection, and pattern reductions.
 *
 * Designed to run without Android dependencies so that it can be executed in pure JVM unit tests.
 */
object SpamScorer {

    const val THRESHOLD_SPAM = 60
    const val THRESHOLD_SUSPICIOUS = 30

    // Weights
    const val WEIGHT_LINK = 25
    const val WEIGHT_SHORT_URL = 15
    const val WEIGHT_RISKY_TLD = 20
    const val WEIGHT_SUSPICIOUS_DOMAIN = 15
    const val WEIGHT_ADVANCE_FEE = 25
    const val WEIGHT_SPAM_KEYWORD = 20
    const val MAX_SPAM_KEYWORD_SCORE = 50
    const val WEIGHT_MONEY_PRIZE = 20
    const val WEIGHT_URGENCY = 20
    const val WEIGHT_CREDENTIAL_REQUEST = 40
    const val WEIGHT_IMPERSONATION = 30
    const val WEIGHT_ALPHANUMERIC_HIGH_RISK = 20
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

    private val LINK_REGEX = Regex(
        "(?:(?:https?://|www\\.)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?::\\d+)?(?:/[^\\s]*)?)|" +
            "(?:https?://(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?(?:/[^\\s]*)?|" +
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+(?:/[^\\s]*)?|/[^\\s]+))|" +
            "(?:\\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.(?:[a-zA-Z]{2,10})(?::\\d+)?(?:/[^\\s]*)?\\b)",
        RegexOption.IGNORE_CASE
    )

    private val SHORT_URL_REGEX = Regex(
        "\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd|buff\\.ly|ow\\.ly|rebrand\\.ly|" +
            "goo\\.gl|cutt\\.ly|shorturl\\.at|rb\\.gy|trib\\.al|v\\.gd|tiny\\.cc|bit\\.do)/",
        RegexOption.IGNORE_CASE
    )

    private val RISKY_TLD_REGEX = Regex(
        "\\.(?:xyz|top|info|club|biz|online|site|click|live|icu|buzz|space|tech|shop|vip)(?:[/\\s:]|$)",
        RegexOption.IGNORE_CASE
    )

    private val SUSPICIOUS_HYPHEN_DOMAIN_REGEX = Regex(
        "\\b[a-zA-Z0-9.-]*(?:-(?:hbl|meezan|alfalah|ubl|mcb|bank|ebank|login|daraz|jazz|telenor|" +
            "zong|ufone|jazzcash|easypaisa|sadapay|nayapay|pta|bisp|ehsaas|secure|auth|claim|reward|" +
            "verify|account|apple|google)|(?:hbl|meezan|alfalah|ubl|mcb|bank|ebank|login|daraz|jazz|" +
            "telenor|zong|ufone|jazzcash|easypaisa|sadapay|nayapay|pta|bisp|ehsaas|secure|auth|claim|" +
            "reward|verify|account|apple|google)-)[a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}\\b",
        RegexOption.IGNORE_CASE
    )

    // Credential requests: request verb near sensitive item (both verb-first and noun-first)
    private val CREDENTIAL_VERB_FIRST = Regex(
        "(?<!never |do not |don't |na |kisi se |will never )\\b" +
            "(?:share|send|enter|provide|confirm|submit|forward|" +
            "bhej(?:o|en|ain)?|batain|dal(?:ain|o|e)?|likh(?:ain|o)?)\\b" +
            "(?:\\s+\\S+){0,3}\\s+" +
            "\\b(?:pin|mpin|otp|cvv|password|passcode|secret\\s*(?:code|pin)|cnic|id\\s*card(?:\\s*number)?)\\b"
    )

    private val CREDENTIAL_NOUN_FIRST = Regex(
        "\\b(?:pin|mpin|otp|cvv|password|passcode|secret\\s*(?:code|pin)|cnic|id\\s*card(?:\\s*number)?)\\b" +
            "(?:\\s+\\S+){0,3}\\s+" +
            "(?<!never |do not |don't |na |kisi se |will never )\\b" +
            "(?:send|bhej(?:o|en|ain)?|share|batain|karain|kren|krain|" +
            "provide|enter|submit|dal(?:ain|o|e)?|likh(?:ain|o)?)\\b"
    )

    private val CREDENTIAL_PATTERNS = listOf(
        CREDENTIAL_VERB_FIRST,
        CREDENTIAL_NOUN_FIRST,
        Regex("\\b(?:atm\\s*pin|cvv|card\\s*expiry)\\b.*\\b(?:send|bhej|share|batain|verify)\\b"),
        Regex("\\b(?:verify|update)\\b\\s+(?:your|ur)?\\s*\\b(?:identity|cnic|atm|pin|cvv)\\b")
    )

    // Advance-fee fraud: fee/charge/tax/registration demand coupled with prize, job, visa, loan or subsidy context
    private val ADVANCE_FEE_DEMAND = Regex(
        "(?:pay|send|transfer|deposit|jama|adayeegi|bhej(?:o|en|ain)?)\\s+.*" +
            "\\b(?:fee|charges|tax|registration|deposit|advance)\\b|" +
            "\\b(?:fee|charges|tax|registration|advance)\\b.*" +
            "\\b(?:pay|send|transfer|deposit|jama|bhej(?:o|en|ain)?|karain|krain)\\b"
    )

    private val ADVANCE_FEE_CONTEXT = Regex(
        "\\b(?:prize|lottery|inam|job|visa|loan|qarz|subsidy|pension|welfare|" +
            "relief|customs|auction|parcel|gift|fund|wazeefa|kist|ticket)\\b"
    )

    // Impersonation: Institutions/brands combined with personal mobile senders
    private val INSTITUTION_PATTERNS = listOf(
        Regex("\\b(?:bisp|benazir|ehsaas|8171|jazzcash|easypaisa|pta|fbr|nadra)\\b"),
        Regex("\\b(?:hbl|meezan|alfalah|ubl|mcb|allied|standard\\s*chartered|faysal|sadapay|nayapay|bank)\\b"),
        Regex("\\b(?:tcs|dhl|leopard|daraz|bykea|careem|uber|foodpanda)\\b"),
        Regex("\\b(?:jazz|telenor|zong|ufone|wapda|k-electric|sngpl|customs|pak\\s*army)\\b"),
        Regex("(?:بے نظیر|8171|احساس|بینک|واپڈا)")
    )

    private val ACTION_PATTERNS = listOf(
        Regex(
            "\\b(?:call|contact|rabta|rabtah|claim|wasool|send|" +
                "bhej(?:o|en|ain)?|share|batain|verify|tasdeeq|click|link|update|adjust)\\b"
        ),
        Regex("https?://"),
        Regex("(?:رابطہ|کال|دعویٰ|حاصل)")
    )

    // Money or prize language
    private val PRIZE_PATTERNS = listOf(
        Regex(
            "\\b(?:winner|congratulations|congrats|mubarak(?:\\s*ho)?|" +
                "prize|jackpot|lucky\\s*draw|qurandazi|lottery|gold\\s*bar|honda\\s*(?:125|city)?|\\bcar\\b)\\b"
        ),
        Regex(
            "(?:you\\s*(?:have)?\\s*won|aap\\s*jeet\\s*chuke|\\binam\\b|" +
                "\\bwazeefa\\b|cash\\s*reward|reward|kist\\s*(?:wasool|jari|mil|aa\\s*gayi)|voucher)\\b"
        ),
        Regex("(?:rs\\.?|pkr|\\$)\\s*[0-9,]+\\s*(?:inam|prize|cash|jeet|wazeefa|kist|reward|bonus)\\b"),
        Regex("(?:received|withdraw).*(?:btc|bitcoin|crypto|wallet|profit|\\$[0-9,]+)"),
        Regex("(?:مبارک|انعام|لاٹری|قرعہ اندازی|وظیفہ|دعویٰ)")
    )

    // Urgency & Threat language
    private val URGENCY_PATTERNS = listOf(
        Regex(
            "\\b(?:urgent|immediately|act\\s*now|action\\s*required|" +
                "last\\s*chance|final\\s*notice|deactivation|warning|notice|" +
                "disconnect(?:ed|ing)?|suspended|unauthorized|activity\\s*detected)\\b"
        ),
        Regex(
            "(?:within\\s*\\d+\\s*(?:hours|ghanty)|24\\s*hours|24\\s*ghanty|" +
                "account\\s*(?:will\\s*be|is)\\s*suspended|sim\\s*block)"
        ),
        Regex(
            "(?:block\\s*hone\\s*se\\s*bach(?:ayein|ain|ne)|" +
                "fauran|foran|fori|abhi|arrest|legal\\s*action|gher\\s*qanooni|" +
                "avoid\\s*(?:permanent)?\\s*closure|restore\\s*krwane)"
        ),
        Regex("(?:service\\s*(?:termination|interruption)|immediate\\s*verification)"),
        Regex("(?:فوراً|بند ہو|بلاک|غیر قانونی)")
    )

    // English spam keyword phrases
    private val ENGLISH_SPAM_KEYWORDS = listOf(
        Regex("claim\\s*(?:your)?\\s*free"),
        Regex("exclusive\\s*(?:deal|offer)"),
        Regex("guaranteed\\s*(?:return|profit|income|approval|2\\s*lakh)"),
        Regex("click\\s*(?:the\\s*link\\s*)?to\\s*claim"),
        Regex("(?:instant|urgent|easy|fast|pre-?approved|paperless)\\s*(?:cash|loan)"),
        Regex("earn\\s*(?:\\$|rs\\.?|pkr)?\\s*[0-9,]+\\s*(?:daily|weekly|from\\s*home)"),
        Regex("work\\s*from\\s*home"),
        Regex("no\\s*(?:investment|experience|guarantor)\\s*needed"),
        Regex("double\\s*your\\s*(?:money|income)"),
        Regex("(?:unpaid|due)\\s*invoice.*settle"),
        Regex(
            "(?:security\\s*breach|unusual\\s*sign-in|account\\s*locked|" +
                "unauthorized|verification\\s*pending|biometric\\s*inactivity).*verify"
        ),
        Regex("pay\\s*(?:release|customs|delivery|transfer)?\\s*fee"),
        Regex("limited\\s*(?:vouchers|time|slots|stock)"),
        Regex("(?:zero|0%|no)\\s*(?:percent|%|interest|mark-?up)")
    )

    // Roman Urdu & Local scam keyword phrases
    private val ROMAN_URDU_SPAM_KEYWORDS = listOf(
        Regex(
            "(?:bisp|benazir|ehsaas|8171).*" +
                "(?:balance|wazeefa|rashan|claim|fauran|foran|rabta|rabtah|paise|kist|" +
                "mil\\s*gaye|jaanch|kafalat|taleem|verify|relief)"
        ),
        Regex("(?:lottery|inam|prize).*(?:nikli|nikla|lagi|mubarak|jeet|claim|wasool|lene)"),
        Regex("jeeto\\s*pakistan"),
        Regex("qurandazi.*(?:naam|inam|result|cash)"),
        Regex("(?:sim|account|number).*(?:band|block|suspend|deactivat)"),
        Regex("(?:jazzcash|easypaisa).*(?:block|suspend|lottery|inam|waseela|error|unblock)"),
        Regex("(?:pta|fbr).*(?:warning|alert|rule|verification|tax|illegal|terrorist|customs)"),
        Regex("ghar\\s*baith(?:ay|e).*kamain"),
        Regex("online\\s*(?:karobar|investment|kamai)"),
        Regex("bina\\s*(?:kisi\\s*)?investment"),
        Regex("qarz\\s*(?:bila|bina)\\s*sood"),
        Regex("(?:call|rabta|rabtah|contact)\\s*(?:karain|karein|farmain|kijiye|krain).*03[0-9]{9}"),
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
        Regex("\\b(?:debited|credited|spent)\\s*(?:by|with|for|to|on)?\\s*(?:rs\\.?|pkr|inr|usd|\\$)?\\s*[0-9,]+"),
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

        val formattingReason = checkFormatting(body)
        if (formattingReason != null) {
            score += WEIGHT_CAPITALS_EXCLAMATION
            reasons.add(formattingReason)
        }

        val normalizedBody = body.lowercase(Locale.ROOT).replace(Regex("\\s+"), " ")

        val linkEval = evaluateLinks(normalizedBody)
        score += linkEval.score
        reasons.addAll(linkEval.reasons)

        val content = evaluateContentSignals(normalizedBody)
        score += content.score
        reasons.addAll(content.reasons)

        if (isImpersonatingBrandFromMobile(address, normalizedBody)) {
            score += WEIGHT_IMPERSONATION
            reasons.add("Institution / brand impersonation from mobile number (+$WEIGHT_IMPERSONATION)")
        }

        if (isAlphanumericHighRisk(
                address,
                content.hasCredential,
                linkEval.hasLink,
                content.hasUrgency,
                content.hasPrize,
                normalizedBody
            )
        ) {
            score += WEIGHT_ALPHANUMERIC_HIGH_RISK
            reasons.add("High-risk alphanumeric / shortcode phishing pattern (+$WEIGHT_ALPHANUMERIC_HIGH_RISK)")
        }

        val isOtp = OTP_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        val isTxn = TRANSACTION_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        val isStrongAttack = content.hasCredential || (content.hasPrize && linkEval.hasLink)

        if (!isStrongAttack && !content.hasCredential) {
            if (isOtp) {
                score -= REDUCTION_OTP
                reasons.add("Legitimate OTP / verification code pattern (-$REDUCTION_OTP)")
            }
            if (isTxn) {
                score -= REDUCTION_TRANSACTION
                reasons.add("Legitimate transaction / balance alert pattern (-$REDUCTION_TRANSACTION)")
            }
        }

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
        if (!LINK_REGEX.containsMatchIn(normalizedBody)) {
            return LinkEvaluation(0, emptyList(), false)
        }

        var linkScore = WEIGHT_LINK
        val reasons = mutableListOf("Link detected (+$WEIGHT_LINK)")

        if (SHORT_URL_REGEX.containsMatchIn(normalizedBody)) {
            linkScore += WEIGHT_SHORT_URL
            reasons.add("Shortened URL service (+$WEIGHT_SHORT_URL)")
        }

        if (RISKY_TLD_REGEX.containsMatchIn(normalizedBody)) {
            linkScore += WEIGHT_RISKY_TLD
            reasons.add("Risky / throwaway domain TLD (+$WEIGHT_RISKY_TLD)")
        }

        if (SUSPICIOUS_HYPHEN_DOMAIN_REGEX.containsMatchIn(normalizedBody)) {
            linkScore += WEIGHT_SUSPICIOUS_DOMAIN
            reasons.add("Suspicious hyphenated brand/security domain (+$WEIGHT_SUSPICIOUS_DOMAIN)")
        }

        return LinkEvaluation(linkScore, reasons, true)
    }

    private data class ContentSignals(
        val score: Int,
        val reasons: List<String>,
        val hasCredential: Boolean,
        val hasPrize: Boolean,
        val hasUrgency: Boolean,
    )

    private fun evaluateContentSignals(normalizedBody: String): ContentSignals {
        var score = 0
        val reasons = mutableListOf<String>()

        val hasCredential = CREDENTIAL_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        if (hasCredential) {
            score += WEIGHT_CREDENTIAL_REQUEST
            reasons.add("Sensitive credential request (+$WEIGHT_CREDENTIAL_REQUEST)")
        }

        val hasPrize = PRIZE_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        if (hasPrize) {
            score += WEIGHT_MONEY_PRIZE
            reasons.add("Prize / lottery / cash language (+$WEIGHT_MONEY_PRIZE)")
        }

        val hasUrgency = URGENCY_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        if (hasUrgency) {
            score += WEIGHT_URGENCY
            reasons.add("Urgent action / suspension threat (+$WEIGHT_URGENCY)")
        }

        if (ADVANCE_FEE_DEMAND.containsMatchIn(normalizedBody) &&
            ADVANCE_FEE_CONTEXT.containsMatchIn(normalizedBody)
        ) {
            score += WEIGHT_ADVANCE_FEE
            reasons.add("Advance-fee fraud pattern (+$WEIGHT_ADVANCE_FEE)")
        }

        val enCount = ENGLISH_SPAM_KEYWORDS.count { it.containsMatchIn(normalizedBody) }
        val urCount = ROMAN_URDU_SPAM_KEYWORDS.count { it.containsMatchIn(normalizedBody) }
        val keywordCount = enCount + urCount
        if (keywordCount > 0) {
            val keywordScore = min(keywordCount * WEIGHT_SPAM_KEYWORD, MAX_SPAM_KEYWORD_SCORE)
            reasons.add("Spam keywords matched ($keywordCount match(es), +$keywordScore)")
            score += keywordScore
        }

        return ContentSignals(score, reasons, hasCredential, hasPrize, hasUrgency)
    }

    private fun isImpersonatingBrandFromMobile(address: String, normalizedBody: String): Boolean {
        val clean = address.trim().replace(Regex("[\\s-+()]"), "")
        val isMobile = clean.length >= MIN_MOBILE_NUMBER_LENGTH && clean.all { it.isDigit() }
        if (!isMobile) return false

        val namesInstitution = INSTITUTION_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        val hasAction = ACTION_PATTERNS.any { it.containsMatchIn(normalizedBody) }
        return namesInstitution && hasAction
    }

    private fun isAlphanumericHighRisk(
        address: String,
        hasCredential: Boolean,
        hasLink: Boolean,
        hasUrgency: Boolean,
        hasPrize: Boolean,
        normalizedBody: String
    ): Boolean {
        val clean = address.trim().replace(Regex("[\\s-+()]"), "")
        val isMobile = clean.length >= MIN_MOBILE_NUMBER_LENGTH && clean.all { it.isDigit() }
        if (isMobile) {
            return false
        }

        val hasContactCTA = normalizedBody.contains("call") || normalizedBody.contains("rabta") || hasLink
        return hasCredential || (hasLink && hasUrgency) || (hasPrize && hasContactCTA)
    }

    private fun isSuspiciousSender(address: String, isOtp: Boolean, isTxn: Boolean): Boolean {
        if (isOtp || isTxn) {
            return false
        }
        val clean = address.trim().removePrefix("+")
        if (clean.isEmpty()) {
            return false
        }
        val isAlphanumeric = clean.any { it.isLetter() }
        val isShortcode = clean.all { it.isDigit() } && clean.length in MIN_SHORTCODE_LENGTH..MAX_SHORTCODE_LENGTH
        return isAlphanumeric || isShortcode
    }
}
