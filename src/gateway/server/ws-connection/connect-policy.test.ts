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
    const nonControlUi = resolveControlUiAuthPolicy({
      isControlUi: false,
      controlUiConfig: undefined,
      deviceRaw: null,
    });

    test("trusted-proxy operator Control UI skips pairing without dangerouslyDisableDeviceAuth", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthOk: true,
        }),
      ).toBe(true);
    });

    test("trusted-proxy webchat operator skips pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: nonControlUi,
          role: "operator",
          isControlUi: false,
          isWebchat: true,
          sharedAuthOk: true,
          trustedProxyAuthOk: true,
        }),
      ).toBe(true);
    });

    test("token/password shared auth still requires pairing for Control UI", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthOk: false,
        }),
      ).toBe(false);
    });

    test("token/password shared auth skips pairing for non-browser operator (CLI)", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: nonControlUi,
          role: "operator",
          isControlUi: false,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthOk: false,
        }),
      ).toBe(true);
    });

    test("dangerouslyDisableDeviceAuth bypass still skips Control UI pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: bypassControlUi,
          role: "operator",
          isControlUi: true,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthOk: false,
        }),
      ).toBe(true);
    });

    test("node role never skips pairing, even with trusted-proxy auth", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: nonControlUi,
          role: "node",
          isControlUi: false,
          isWebchat: false,
          sharedAuthOk: true,
          trustedProxyAuthOk: true,
        }),
      ).toBe(false);
    });

    test("no shared auth and no trusted proxy requires pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: nonControlUi,
          role: "operator",
          isControlUi: false,
          isWebchat: false,
          sharedAuthOk: false,
          trustedProxyAuthOk: false,
        }),
      ).toBe(false);
    });
  });
});
