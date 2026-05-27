import type { ConnectParams } from "../../protocol/index.js";
import type { GatewayRole } from "../../role-policy.js";
import { roleCanSkipDeviceIdentity } from "../../role-policy.js";

export type ControlUiAuthPolicy = {
  allowInsecureAuthConfigured: boolean;
  dangerouslyDisableDeviceAuth: boolean;
  allowBypass: boolean;
  device: ConnectParams["device"] | null | undefined;
};

export function resolveControlUiAuthPolicy(params: {
  isControlUi: boolean;
  controlUiConfig:
    | {
        allowInsecureAuth?: boolean;
        dangerouslyDisableDeviceAuth?: boolean;
      }
    | undefined;
  deviceRaw: ConnectParams["device"] | null | undefined;
}): ControlUiAuthPolicy {
  const allowInsecureAuthConfigured =
    params.isControlUi && params.controlUiConfig?.allowInsecureAuth === true;
  const dangerouslyDisableDeviceAuth =
    params.isControlUi && params.controlUiConfig?.dangerouslyDisableDeviceAuth === true;
  return {
    allowInsecureAuthConfigured,
    dangerouslyDisableDeviceAuth,
    // `allowInsecureAuth` must not bypass secure-context/device-auth requirements.
    allowBypass: dangerouslyDisableDeviceAuth,
    device: dangerouslyDisableDeviceAuth ? null : params.deviceRaw,
  };
}

export function shouldSkipControlUiPairing(
  policy: ControlUiAuthPolicy,
  sharedAuthOk: boolean,
): boolean {
  return policy.allowBypass && sharedAuthOk;
}

/**
 * Decide whether a connecting client may skip per-device pairing.
 *
 * Pairing binds a cryptographic device key on first connect. It is skipped when
 * gateway-level trust is already established by other means:
 *  - Control UI with `dangerouslyDisableDeviceAuth`.
 *  - Trusted-proxy auth: the reverse proxy authenticated the user (verified
 *    source IP + signed user header), so pairing is redundant. Unlike a shared
 *    token/password, no stealable secret lives in the browser, so this also
 *    covers Control UI / webchat operator connections.
 *  - Shared token/password for non-browser operator clients (e.g. CLI). Browser
 *    surfaces still pair so a device key is bound on first use.
 */
export function shouldSkipDevicePairing(params: {
  controlUiAuthPolicy: ControlUiAuthPolicy;
  role: GatewayRole;
  isControlUi: boolean;
  isWebchat: boolean;
  sharedAuthOk: boolean;
  trustedProxyAuthOk: boolean;
}): boolean {
  if (shouldSkipControlUiPairing(params.controlUiAuthPolicy, params.sharedAuthOk)) {
    return true;
  }
  if (params.role !== "operator") {
    return false;
  }
  if (params.trustedProxyAuthOk) {
    return true;
  }
  return params.sharedAuthOk && !params.isControlUi && !params.isWebchat;
}

export type MissingDeviceIdentityDecision =
  | { kind: "allow" }
  | { kind: "reject-control-ui-insecure-auth" }
  | { kind: "reject-unauthorized" }
  | { kind: "reject-device-required" };

export function evaluateMissingDeviceIdentity(params: {
  hasDeviceIdentity: boolean;
  role: GatewayRole;
  isControlUi: boolean;
  controlUiAuthPolicy: ControlUiAuthPolicy;
  sharedAuthOk: boolean;
  authOk: boolean;
  hasSharedAuth: boolean;
  isLocalClient: boolean;
}): MissingDeviceIdentityDecision {
  if (params.hasDeviceIdentity) {
    return { kind: "allow" };
  }
  if (params.isControlUi && !params.controlUiAuthPolicy.allowBypass) {
    // Allow localhost Control UI connections when allowInsecureAuth is configured.
    // Localhost has no network interception risk, and browser SubtleCrypto
    // (needed for device identity) is unavailable in insecure HTTP contexts.
    // Remote connections are still rejected to preserve the MitM protection
    // that the security fix (#20684) intended.
    if (!params.controlUiAuthPolicy.allowInsecureAuthConfigured || !params.isLocalClient) {
      return { kind: "reject-control-ui-insecure-auth" };
    }
  }
  if (roleCanSkipDeviceIdentity(params.role, params.sharedAuthOk)) {
    return { kind: "allow" };
  }
  if (!params.authOk && params.hasSharedAuth) {
    return { kind: "reject-unauthorized" };
  }
  return { kind: "reject-device-required" };
}
