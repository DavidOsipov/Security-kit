# Third-Party Notices

This project incorporates code, concepts, and security principles from the following open-source software and academic research. We are grateful to the authors and contributors for their work, which has been instrumental in hardening this library.

---

## Incorporated Software Libraries

This section details third-party software whose code is directly included or adapted within this project.

### lru-cache

-   **Project:** https://github.com/isaacs/node-lru-cache
-   **Copyright:** 2010-2023 Isaac Z. Schlueter and Contributors
-   **License:** ISC

The `SecureLRUCache` component in this security-kit is a modified and security-hardened version of `lru-cache`. The original license text is provided below:

> The ISC License
>
> Copyright (c) 2010-2023 Isaac Z. Schlueter and Contributors
>
> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
> WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
> ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
> ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
> IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


### Inboxfuscation

-   **Project:** https://github.com/Permiso-io-tools/Inboxfuscation
-   **Copyright:** Copyright (c) 2025 Permiso Security
-   **License:** Apache License, Version 2.0

This project's library `canonical.ts` adapts Unicode security concepts and detection patterns demonstrated in the Inboxfuscation framework. Specifically, the logic for identifying and categorizing potentially malicious Unicode characters (such as zero-width characters, RTL control characters, and homoglyphs) was influenced by their comprehensive detection engine.

The full text of the Apache License 2.0, under which this code is licensed, is available in this repository.

---

## Academic and Security Research Influences

This section acknowledges the key academic papers and technical reports whose findings have directly informed the security architecture and defensive coding patterns within this library.

### Module `canonical.ts` is based on:

#### Trojan Source: Invisible Vulnerabilities

-   **Authors:** Nicholas Boucher, Ross Anderson
-   **Publication:** 32nd USENIX Security Symposium, 2021
-   **Link:** https://www.usenix.org/conference/usenixsecurity21/presentation/boucher
-   **Influence on this Library:** This paper is the primary motivation for detecting and rejecting Unicode bidirectional (Bidi) control characters. The `validateUnicodeSecurity` and `detectTrojanSourcePatterns` functions are direct countermeasures against the "invisible vulnerabilities" and visual deception attacks described in this work.

#### Initial Analysis of Underhanded Source Code

-   **Author:** David A. Wheeler
-   **Publication:** Institute for Defense Analyses (IDA) Document D-13166, April 2020
-   **Link:** https://apps.dtic.mil/sti/pdfs/AD1122149.pdf
-   **Influence on this Library:** This work informs the library's core "Zero Trust" philosophy regarding input. It highlights the long-standing practice of writing malicious code that appears benign to human reviewers. This justifies our strict, multi-layered validation approach and the principle of "failing loudly" when encountering suspicious constructs like homoglyphs or invisible characters.

#### Host/Split: Exploitable Antipatterns in Unicode Normalization

-   **Author:** Jonathan Birch
-   **Publication:** Microsoft Technical Whitepaper
-   **Influence on this Library:** This paper is the direct inspiration for the "validate, normalize, re-validate" pattern in `normalizeInputString`. It demonstrates how Unicode normalization (specifically NFKC/NFKD) can introduce syntactically significant characters (e.g., `/`, `@`, `#`) into a string, leading to security bypasses. Our re-validation step after normalization is a direct mitigation for this attack class.

#### Special-Character Adversarial Attacks on Open-Source Language Models

-   **Authors:** Ephraiem Sarabamoun
-   **Publication:** arXiv:2508.14070v1 [cs.CR], August 2025
-   **Link:** https://arxiv.org/abs/2508.14070
-   **Influence on this Library:** This research connects modern Unicode abuse to Denial of Service (DoS) vectors. The concept of "token expansion" directly informs our implementation of "normalization bomb" protection in `normalizeInputString`, specifically the checks that limit both the absolute input size and the expansion ratio after normalization.

#### ShamFinder: An Automated Framework for Detecting IDN Homographs

-   **Authors:** Hiroaki Suzuki, Daiki Chiba, Yoshiro Yoneya, Tatsuya Mori, and Shigeki Goto
-   **Publication:** Proceedings of the ACM Internet Measurement Conference (IMC '19)
-   **DOI:** https://doi.org/10.1145/3355369.3355587
-   **Influence on this Library:** This paper provides a deep analysis of automated homoglyph detection. It justifies the inclusion of a proactive homoglyph check (`HOMOGLYPH_SUSPECTS`) in `validateUnicodeSecurity` as a necessary defense against phishing and spoofing attacks that rely on visually confusable characters.
-   

#### The Unicode Standard and Technical Reports

-   **Organization:** The Unicode Consortium
-   **Link:** https://www.unicode.org/reports/
-   **Influence on this Library:** The architectural approach to Unicode security in `canonical.ts` library is directly based on the formal specifications and best practices published by the Unicode Consortium. The following documents were essential references:
    -   **UAX #15: Unicode Normalization Forms:** Provided the foundational concepts for the "validate, normalize, re-validate" security pattern. It details how normalization can change string content, which is a critical consideration for preventing security bypasses.
    -   **UAX #31: Unicode Identifier and Syntax:** Informed the logic for distinguishing between valid identifier characters and syntactic characters, which is crucial for robust parsing and preventing syntax injection attacks.
    -   **UTS #39: Unicode Security Mechanisms:** This was a primary source for the library's threat model. It provided the data and algorithms for detecting confusable characters (homoglyphs), mixed-script spoofing, and identifying characters that are restricted for security reasons.
    -   **UTS #55: Unicode Source Code Handling:** Provided high-level guidance and motivation for building security tools that are aware of the unique challenges posed by Unicode in programming and scripting environments.