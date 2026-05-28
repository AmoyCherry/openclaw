import { describe, expect, test } from "vitest";
import {
  evaluateMissingDeviceIdentity,
  resolveControlUiAuthPolicy,
  shouldSkipControlUiPairing,
  shouldSkipDevicePairing,
} from "./connect-policy.js";

describe("ws connect policy", () => {
  test("resolves control-ui auth policy", () => {
    const bypass = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: {
        id: "dev-1",
        publicKey: "pk",
        signature: "sig",
        signedAt: Date.now(),
        nonce: "nonce-1",
      },
    });
    expect(bypass.allowBypass).toBe(true);
    expect(bypass.device).toBeNull();

    const regular = resolveControlUiAuthPolicy({
      isControlUi: false,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: {
        id: "dev-2",
        publicKey: "pk",
        signature: "sig",
        signedAt: Date.now(),
        nonce: "nonce-2",
      },
    });
    expect(regular.allowBypass).toBe(false);
    expect(regular.device?.id).toBe("dev-2");
  });

  test("evaluates missing-device decisions", () => {
    const policy = resolveControlUiAuthPolicy({
      isControlUi: false,
      controlUiConfig: undefined,
      deviceRaw: null,
    });

    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: true,
        role: "node",
        isControlUi: false,
        controlUiAuthPolicy: policy,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: false,
      }).kind,
    ).toBe("allow");

    const controlUiStrict = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: { allowInsecureAuth: true, dangerouslyDisableDeviceAuth: false },
      deviceRaw: null,
    });
    // Remote Control UI with allowInsecureAuth -> still rejected.
    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiStrict,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: false,
      }).kind,
    ).toBe("reject-control-ui-insecure-auth");

    // Local Control UI with allowInsecureAuth -> allowed.
    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiStrict,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: true,
      }).kind,
    ).toBe("allow");

    // Control UI without allowInsecureAuth, even on localhost -> rejected.
    const controlUiNoInsecure = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: false },
      deviceRaw: null,
    });
    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiNoInsecure,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: true,
      }).kind,
    ).toBe("reject-control-ui-insecure-auth");

    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "operator",
        isControlUi: false,
        controlUiAuthPolicy: policy,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: false,
      }).kind,
    ).toBe("allow");

    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "operator",
        isControlUi: false,
        controlUiAuthPolicy: policy,
        sharedAuthOk: false,
        authOk: false,
        hasSharedAuth: true,
        isLocalClient: false,
      }).kind,
    ).toBe("reject-unauthorized");

    expect(
      evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "node",
        isControlUi: false,
        controlUiAuthPolicy: policy,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: false,
      }).kind,
    ).toBe("reject-device-required");
  });

  test("pairing bypass requires control-ui bypass + shared auth", () => {
    const bypass = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: null,
    });
    const strict = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: undefined,
      deviceRaw: null,
    });
    expect(shouldSkipControlUiPairing(bypass, true)).toBe(true);
    expect(shouldSkipControlUiPairing(bypass, false)).toBe(false);
    expect(shouldSkipControlUiPairing(strict, true)).toBe(false);
  });

  describe("shouldSkipDevicePairing", () => {
    const strictControlUi = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: undefined,
      deviceRaw: null,
    });
    const bypassControlUi = resolveControlUiAuthPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: null,
    });

    test("trusted-proxy auth skips pairing for Control UI (regression for #issue)", () => {
      // Trusted-proxy mode: the proxy already authenticated the user, so the browser
      // Control UI must not be forced into device pairing.
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: true,
          sharedAuthOk: true,
          trustedProxyAuthenticated: true,
        }),
      ).toBe(true);
    });

    test("trusted-proxy auth skips pairing for webchat clients", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: false,
          isWebchat: true,
          sharedAuthOk: true,
          trustedProxyAuthenticated: true,
        }),
      ).toBe(true);
    });

    test("shared token/password alone does NOT skip pairing for browser clients", () => {
      // Without trusted-proxy or dangerouslyDisableDeviceAuth, browser clients still pair.
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: true,
          sharedAuthOk: true,
          trustedProxyAuthenticated: false,
        }),
      ).toBe(false);
    });

    test("shared token/password skips pairing for non-browser operator clients (CLI)", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: false,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthenticated: false,
        }),
      ).toBe(true);
    });

    test("dangerouslyDisableDeviceAuth + shared auth skips pairing for Control UI", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: bypassControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: true,
          sharedAuthOk: true,
          trustedProxyAuthenticated: false,
        }),
      ).toBe(true);
    });

    test("non-operator roles never skip pairing via shared/trusted-proxy auth", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "node",
          isControlUi: false,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthenticated: true,
        }),
      ).toBe(false);
    });

    test("no auth means no skip", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: true,
          sharedAuthOk: false,
          trustedProxyAuthenticated: false,
        }),
      ).toBe(false);
    });
  });
});
