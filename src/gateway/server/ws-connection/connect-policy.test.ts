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
    const noControlUi = resolveControlUiAuthPolicy({
      isControlUi: false,
      controlUiConfig: undefined,
      deviceRaw: null,
    });

    test("trusted-proxy auth skips pairing for the Control UI", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "trusted-proxy",
          isControlUi: true,
          isWebchat: false,
        }),
      ).toBe(true);
    });

    test("trusted-proxy auth skips pairing for webchat", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: noControlUi,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "trusted-proxy",
          isControlUi: false,
          isWebchat: true,
        }),
      ).toBe(true);
    });

    test("browser-held shared token/password still requires Control UI pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "token",
          isControlUi: true,
          isWebchat: false,
        }),
      ).toBe(false);
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: noControlUi,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "password",
          isControlUi: false,
          isWebchat: true,
        }),
      ).toBe(false);
    });

    test("non-browser operator shared auth skips pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: noControlUi,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "token",
          isControlUi: false,
          isWebchat: false,
        }),
      ).toBe(true);
    });

    test("node role never skips pairing via shared/trusted-proxy auth", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: noControlUi,
          role: "node",
          sharedAuthOk: true,
          authMethod: "trusted-proxy",
          isControlUi: false,
          isWebchat: false,
        }),
      ).toBe(false);
    });

    test("no shared auth never skips pairing", () => {
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: strictControlUi,
          role: "operator",
          sharedAuthOk: false,
          authMethod: undefined,
          isControlUi: true,
          isWebchat: false,
        }),
      ).toBe(false);
    });

    test("dangerouslyDisableDeviceAuth bypass still skips Control UI pairing", () => {
      const bypass = resolveControlUiAuthPolicy({
        isControlUi: true,
        controlUiConfig: { dangerouslyDisableDeviceAuth: true },
        deviceRaw: null,
      });
      expect(
        shouldSkipDevicePairing({
          controlUiAuthPolicy: bypass,
          role: "operator",
          sharedAuthOk: true,
          authMethod: "none",
          isControlUi: true,
          isWebchat: false,
        }),
      ).toBe(true);
    });
  });
});
