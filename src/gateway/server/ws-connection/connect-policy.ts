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
 * Decide whether device pairing can be skipped on connect.
 *
 * Pairing is skipped when any of these hold:
 * - Control UI opted out of device auth via `dangerouslyDisableDeviceAuth` and shared
 *   auth succeeded (see {@link shouldSkipControlUiPairing}).
 * - An operator client authenticated with a shared token/password. Browser clients
 *   (Control UI / webchat) are excluded here and still pair as a MitM safeguard.
 * - An operator client authenticated via trusted-proxy mode. The reverse proxy already
 *   vouches for the user (via the configured `userHeader`) and the gateway only honors
 *   that header from trusted proxy source IPs, so per-device pairing is redundant. This
 *   case intentionally includes browser clients: otherwise trusted-proxy deployments
 *   could not load the Control UI without setting `dangerouslyDisableDeviceAuth`.
 */
export function shouldSkipDevicePairing(params: {
  controlUiAuthPolicy: ControlUiAuthPolicy;
  role: GatewayRole;
  isControlUi: boolean;
  isWebchat: boolean;
  sharedAuthOk: boolean;
  trustedProxyAuthenticated: boolean;
}): boolean {
  if (shouldSkipControlUiPairing(params.controlUiAuthPolicy, params.sharedAuthOk)) {
    return true;
  }
  if (params.role !== "operator") {
    return false;
  }
  if (params.trustedProxyAuthenticated) {
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
