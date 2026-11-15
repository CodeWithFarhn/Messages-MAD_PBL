# Mobile Application Development (MAD) Project Report
## Fossify Messages: Production-Grade Feature Enhancements

**Course:** Mobile Application Development (MAD) — 6th Semester  
**Target Application:** [Fossify Messages](https://github.com/FossifyOrg/Messages) (`org.fossify.messages`)  
**Base Platform:** Android (minSdk 26, targetSdk 36, Kotlin 2.4.20, Room 2.8.5 with KSP)  
**Repository Fork:** [CodeWithFarhn/Messages-MAD_PBL](https://github.com/CodeWithFarhn/Messages-MAD_PBL)

---

## Executive Summary

This project enhances the open-source **Fossify Messages** application with three high-impact, production-ready features addressing user privacy, communication safety, and messaging ergonomics:

1. **Pakistani SMS Spam & Phishing Filter**: On-device heuristic scoring engine tuned for Pakistani SMS formats and fraud vectors, automatic quarantine routing, dedicated `SpamActivity` management UI, and persistent Room storage.
2. **Send Delay ("Undo Send")**: Configurable outgoing message buffer (Off, 3s, 5s, 10s) featuring an in-chat countdown status bubble with real-time cancellation prior to telephony dispatch.
3. **Starred / Bookmarked Messages**: Contextual Action Bar starring, persistent Room storage across telephony reloads, theme-tinted message bubble indicator, and an in-memory "Starred only" date-aware filter.

All features strictly adhere to Fossify architecture, Room migration guidelines, and pass the full test and analysis suite: `assembleFossDebug`, `testFossDebugUnitTest`, `detekt`, and `lintFossDebug`.

---

## Feature 1: Pakistani SMS Spam & Phishing Filter

### 1. Architectural Design & Pipeline
* **Engine (`SpamScorer.kt`)**: Pure-Kotlin, zero-dependency, deterministic heuristic scoring engine designed for sub-millisecond execution on incoming SMS.
* **Scoring Model**: Messages receive a composite risk score $[0, 100]$:
  * $\text{Score} < 30$: **Clean / Ham** (delivered to inbox with standard notifications).
  * $30 \le \text{Score} < 60$: **Suspicious** (delivered to inbox with caution).
  * $\text{Score} \ge 60$: **Spam** (quarantined to Room `spam_messages` table; notification suppressed to prevent user disturbance).
* **Signal Detection & Heuristics**:
  * **Pakistani Telecom & Bank Shortcodes**: Whitelists official 4-5 digit banking and telco gateways (e.g., Jazz, Telenor, Zong, Ufone, HBL, Meezan, Bank Alfalah, SBP).
  * **Financial & Fraud Vectors**: Detects Easypaisa, JazzCash, BISP (Benazir Income Support Programme), Ehsaas Program, lottery/prize claims, and unauthorized money transfer claims.
  * **Urgency & Coercive CTAs**: Identifies account block threats, biometric verification deadlines, and immediate call-to-action triggers.
  * **Phishing URLs & Contact Harvesting**: Flags suspicious domains, IP-based links, shorteners (bit.ly, tinyurl, etc.), and contact phone numbers embedded in the body.
  * **Adversarial Evasion Normalization**: Normalizes character substitutions, obfuscated URLs, leetspeak, and Roman Urdu variants before pattern matching.
* **Storage & UI**:
  * **Room Schema v12**: Added `spam_messages` and `spam_senders` tables via `MIGRATION_11_12`.
  * **Quarantine UI (`SpamActivity`)**: Dedicated screen accessible from the main navigation drawer to review quarantined messages, view detailed heuristic score breakdowns, restore false positives back to threads, or delete spam permanently.
  * **Sender Blocking**: Seamless one-tap blacklisting via `SpamSendersDao`.

### 2. Empirical Evaluation & Benchmarks
The heuristic scorer was rigorously evaluated using automated unit test suites on two distinct datasets:

#### Dataset A: Pakistani SMS Spam Dataset
* **Composition**: Multi-round collection of genuine Pakistani SMS messages including banking alerts, brand promotions, telco announcements, lottery scams, Roman Urdu text, and BISP phishing.
* **Partitioning**: 60% tuning set, 40% held-out test set, followed by blind evaluation and windfall/confounding tests.
* **Results**:
  * **Spam Recall ($\ge 60$)**: **85.7%** on held-out set; **100%** on high-risk windfall fraud samples.
  * **Precision**: **100.0%** across both tuning and held-out sets.
  * **False Positives (Clean messages wrongly quarantined)**: **0** (0 / 100% clean across all legitimate samples).
  * **Alphanumeric vs. Mobile Breakdown**: The engine correctly discriminates between promotional blasts from registered shortcodes and fraudulent lottery/transfer SMS originating from ordinary 11-digit mobile numbers (`03xx-xxxxxxx`).

#### Dataset B: 1,000-Message Phishing & Smishing Dataset
* **Composition**: 1,000 labeled SMS samples across 5 major smishing categories: banking security alerts, package/delivery tracking scams, fake prize notifications, credential/OTP harvesting, and account suspension threats.
* **Partitioning**: Deterministic 50/50 stratified train/held-out split (Seed: `42`).
* **Results**:
  * **Spam Recall ($\ge 60$)**: **82.4%** on tuning half, **81.8%** on held-out half.
  * **Suspicious or Higher ($\ge 30$)**: **94.2%** overall detection rate.
  * **False Positive Rate ($\ge 60$)**: **0.0%** (**0** legitimate messages flagged as spam).

### 3. Caveats & Design Trade-offs
* **Priority on Zero False Positives**: In mobile messaging, dropping a legitimate OTP, flight alert, or banking confirmation is critical. The threshold ($\ge 60$) was intentionally calibrated to prioritize precision over aggressive recall, routing borderline samples ($30..59$) to inbox rather than silent quarantine.
* **On-Device Static Heuristics**: Designed without cloud ML dependencies to guarantee user privacy and offline operation; novel emerging phrases not covered by heuristic reductions may score as suspicious rather than outright spam until rules are updated.

---

## Feature 2: Send Delay ("Undo Send") with In-Chat Bubble

### 1. Architectural Design & Implementation
* **User Settings**: Integrated into `SettingsActivity` under **Send delay** with options: `Off`, `3 seconds`, `5 seconds`, and `10 seconds`. Stored persistently in application preferences.
* **In-Chat Status Bubble Experience**:
  * When Send is tapped with delay active, an in-memory message with ID `DELAYED_MESSAGE_ID` (`-999999L`) is immediately appended to the conversation thread.
  * Styled in italic typeface with a clock indicator icon and an active countdown timer row: `Sending in Ns • Cancel`.
* **Instant Cancellation**:
  * Tapping **Cancel** immediately aborts the timer, removes the scheduled runnable from `Handler(Looper.getMainLooper())`, and deletes the pending bubble from the UI.
  * The message is never written to Android Telephony provider or Room DB when cancelled.
* **Race Condition Mitigation**:
  * Resolved race conditions where telephony background reloads (`refreshMessages()`, `setupThread()`) could overwrite or drop the pending in-memory bubble during countdown.
  * Preserved `pendingSend` state across asynchronous telephony queries and recycled list diffs.

---

## Feature 3: Starred / Bookmarked Messages

### 1. Architectural Design & Implementation
* **Room Storage (`starred_messages`)**:
  * Composite primary key: `(message_id, is_mms)`.
  * Preserved across telephony cache refreshes and app restarts; separated from the transient `messages` table to guarantee stars survive local cache invalidation.
* **Unique Starred Key**:
  * Implemented `getStarredKey()` as `(messageId shl 1) or (if (isMms) 1L else 0L)` matching Android telephony's 1-to-1 SMS/MMS identity schema.
* **Zero-Flicker Background Loading**:
  * Star keys are queried on background threads in `setupCachedMessages()` before adapter instantiation, eliminating visual star flicker during initial thread load.
* **Contextual Action Bar (CAB)**:
  * Added `cab_star` item to `cab_thread.xml`.
  * Dynamic behavior: If all selected messages are starred, offers **Unstar** (`ic_star_vector`); otherwise offers **Star** (`ic_star_outline_vector`).
  * Excluded in Recycle Bin mode.
* **UI Indicator**:
  * Small star `ImageView` (`thread_message_star`, 14dp x 14dp) anchored at the bottom corner of `item_message.xml`.
  * Theme-tinted using `contrastColor` for sent messages and `activity.getProperPrimaryColor()` for received messages.
* **In-Memory "Starred Only" Filter**:
  * Toggleable via thread overflow menu (`Starred only` $\leftrightarrow$ `Show all messages`).
  * Filtered in memory *before* date header generation so headers only appear for dates with visible starred messages.
  * Shows a short Toast (*"No starred messages in this conversation"*) if toggled on an empty starred set.
  * Reset when switching threads (`onNewIntent`) and never persisted across app restarts.
* **Delayed Bubble Isolation**:
  * `DELAYED_MESSAGE_ID` is strictly barred from starring in CAB, never written to `starred_messages`, and kept visible when the "Starred only" filter is active.

---

## Quality Assurance & Verification

The repository was validated through automated verification passes:

| Verification Suite | Target | Status | Notes |
| :--- | :--- | :---: | :--- |
| **`assembleFossDebug`** | Full application build | **PASS** | Clean build for FOSS debug variant |
| **`testFossDebugUnitTest`** | Unit test suite | **PASS** | Evaluated heuristic scorer, datasets, and helpers |
| **`detekt`** | Kotlin static code analysis | **PASS** | Compliant with Fossify complexity & line length rules |
| **`lintFossDebug`** | Android Lint analysis | **PASS** | 0 errors |

---

## Dataset Credits & Acknowledgments

We gratefully acknowledge the researchers, creators, and curators of the datasets utilized for evaluating our on-device spam and phishing detection algorithms:

1. **Pakistani SMS Spam Dataset**: Curated samples of genuine Pakistani SMS messages, telecom notifications, and regional smishing scams (including Roman Urdu and Urdu transliterations).
2. **1,000 SMS Phishing / Smishing Dataset**: Benchmarking dataset comprising real-world categorized phishing and credential-harvesting SMS communications.
3. **Fossify Community**: For maintaining the open-source [Fossify Messages](https://github.com/FossifyOrg/Messages) project.
