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
 * Decide whether a connecting client may skip the device-pairing step.
 *
 * Device pairing is primarily a MitM protection for clients that authenticate
 * with a browser-held shared secret (token/password): even with the secret, a
 * new device must be approved. It is unnecessary when trust is established some
 * other way:
 *  - `dangerouslyDisableDeviceAuth` break-glass bypass for the Control UI.
 *  - Trusted-proxy auth: the user identity is vouched for by an external trusted
 *    layer (reverse proxy + network policy) and no browser-held secret is
 *    involved, so pairing is redundant on every surface (CLI, Control UI,
 *    webchat). This is gateway-level operator trust, same as a valid token.
 *  - Non-browser operator clients (e.g. CLI) using shared token/password, where
 *    the secret does not live in an interceptable browser context.
 *
 * The device signature is still verified separately, so skipping pairing does
 * not weaken the proof that the client controls its device key.
 */
export function shouldSkipDevicePairing(params: {
  controlUiAuthPolicy: ControlUiAuthPolicy;
  role: GatewayRole;
  sharedAuthOk: boolean;
  authMethod: string | undefined;
  isControlUi: boolean;
  isWebchat: boolean;
}): boolean {
  if (shouldSkipControlUiPairing(params.controlUiAuthPolicy, params.sharedAuthOk)) {
    return true;
  }
  if (params.role !== "operator" || !params.sharedAuthOk) {
    return false;
  }
  // Trusted-proxy trust comes from network position + proxy-injected identity,
  // not a browser-held secret, so device pairing adds nothing. Applies to all
  // surfaces, including the Control UI.
  if (params.authMethod === "trusted-proxy") {
    return true;
  }
  // Shared token/password is gateway-level operator trust, but browser surfaces
  // still require pairing to protect the browser-held secret against MitM.
  return !params.isControlUi && !params.isWebchat;
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
