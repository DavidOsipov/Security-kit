import noSecretEq from "../eslint-rules/no-secret-eq.js";
import noPostMessageConstantUsage from "../eslint-rules/no-postmessage-constant-usage.js";
import enforceSecureWipe from "../eslint-rules/enforce-secure-wipe.js";
import noUnsealedConfiguration from "../eslint-rules/no-unsealed-configuration.js";
import throwTypedErrors from "../eslint-rules/throw-typed-errors.js";
import enforceTextEncoderDecoder from "../eslint-rules/enforce-text-encoder-decoder.js";
import noDirectSubtleCrypto from "../eslint-rules/no-direct-subtle-crypto.js";
import enforceTestApiGuard from "../eslint-rules/enforce-test-api-guard.js";
import noUnNormalizedStringComparison from "../eslint-rules/no-un-normalized-string-comparison.js";
import noDirectProcessEnv from "../eslint-rules/no-direct-process-env.js";
import noBroadExceptionSwallow from "../eslint-rules/no-broad-exception-swallow.js";
import enforceSealedKitStartup from "../eslint-rules/enforce-sealed-kit-startup.js";
import noMathRandomSecurityContext from "../eslint-rules/no-math-random-security-context.js";
import enforceSecurityKitImports from "../eslint-rules/enforce-security-kit-imports.js";
// New high-priority security rules
import enforceSecureLogging from "../eslint-rules/enforce-secure-logging.js";
import enforceErrorSanitizationAtBoundary from "../eslint-rules/enforce-error-sanitization-at-boundary.js";
import enforceVisibilityAbortPattern from "../eslint-rules/enforce-visibility-abort-pattern.js";
import noDirectUrlConstructor from "../eslint-rules/no-direct-url-constructor.js";
import enforceConfigImmutability from "../eslint-rules/enforce-config-immutability.js";
// PostMessage and signing security rules
import enforceSecurePostmessageListener from "../eslint-rules/enforce-secure-postmessage-listener.js";
import enforceSecureSignerIntegrity from "../eslint-rules/enforce-secure-signer-integrity.js";
import noInsecureNonceStore from "../eslint-rules/no-insecure-nonce-store.js";
import enforcePostmessageConfigConsistency from "../eslint-rules/enforce-postmessage-config-consistency.js";

export default {
  rules: {
    "no-secret-eq": noSecretEq,
    "no-postmessage-constant-usage": noPostMessageConstantUsage,
    "enforce-secure-wipe": enforceSecureWipe,
    "no-unsealed-configuration": noUnsealedConfiguration,
    "throw-typed-errors": throwTypedErrors,
    "enforce-text-encoder-decoder": enforceTextEncoderDecoder,
    "no-direct-subtle-crypto": noDirectSubtleCrypto,
    "enforce-test-api-guard": enforceTestApiGuard,
    "no-un-normalized-string-comparison": noUnNormalizedStringComparison,
    "no-direct-process-env": noDirectProcessEnv,
    "no-broad-exception-swallow": noBroadExceptionSwallow,
    "enforce-sealed-kit-startup": enforceSealedKitStartup,
    "no-math-random-security-context": noMathRandomSecurityContext,
    "enforce-security-kit-imports": enforceSecurityKitImports,
    // New high-priority security rules (OWASP ASVS L3)
    "enforce-secure-logging": enforceSecureLogging,
    "enforce-error-sanitization-at-boundary": enforceErrorSanitizationAtBoundary,
    "enforce-visibility-abort-pattern": enforceVisibilityAbortPattern,
    "no-direct-url-constructor": noDirectUrlConstructor,
    "enforce-config-immutability": enforceConfigImmutability,
    // PostMessage and signing security rules
    "enforce-secure-postmessage-listener": enforceSecurePostmessageListener,
    "enforce-secure-signer-integrity": enforceSecureSignerIntegrity,
    "no-insecure-nonce-store": noInsecureNonceStore,
    "enforce-postmessage-config-consistency": enforcePostmessageConfigConsistency,
  },
};
