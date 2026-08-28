export type WorkspaceCapabilityBoundaryInput = Readonly<{
  authenticated_current_state: boolean;
  explicit_grant: boolean;
  carrier_only_evidence: boolean;
  requested_capabilities: readonly string[];
  workspace_ceiling: readonly string[];
  role_path_ceilings: readonly (readonly string[])[];
  grant_capabilities: readonly string[];
  revoked_effective: boolean;
}>;

type WorkspacePolicyDecision =
  | { verdict: "accept"; normalized: Readonly<Record<string, unknown>> }
  | {
      verdict: "reject";
      reason_code:
        | "workspace_schema_invalid"
        | "checkpoint_stale"
        | "policy_denied"
        | "capability_escalation"
        | "affiliation_stale"
        | "authority_conflict"
        | "device_revoked"
        | "workspace_replay"
        | "resource_unknown"
        | "host_unauthorized"
        | "history_denied";
    };

function canonicalSet(values: readonly string[]): string[] | null {
  if (
    !Array.isArray(values)
    || values.length === 0
    || values.some((value) => typeof value !== "string" || value.length === 0)
    || new Set(values).size !== values.length
  ) return null;
  return [...values].sort();
}

/**
 * Applies Workspace authority only from authenticated current state and one
 * explicit grant, intersecting the workspace, every role path, and grant
 * ceiling before an effect is authorized.
 */
export function evaluateWorkspaceCapabilityBoundary(
  input: WorkspaceCapabilityBoundaryInput,
): WorkspacePolicyDecision {
  if (
    typeof input.authenticated_current_state !== "boolean"
    || typeof input.explicit_grant !== "boolean"
    || typeof input.carrier_only_evidence !== "boolean"
    || typeof input.revoked_effective !== "boolean"
    || !Array.isArray(input.role_path_ceilings)
    || input.role_path_ceilings.length === 0
  ) return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  const requested = canonicalSet(input.requested_capabilities);
  const workspace = canonicalSet(input.workspace_ceiling);
  const grant = canonicalSet(input.grant_capabilities);
  const paths = input.role_path_ceilings.map(canonicalSet);
  if (requested === null || workspace === null || grant === null || paths.includes(null)) {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  if (!input.authenticated_current_state) {
    return { verdict: "reject", reason_code: "checkpoint_stale" };
  }
  if (!input.explicit_grant || input.carrier_only_evidence || input.revoked_effective) {
    return { verdict: "reject", reason_code: "policy_denied" };
  }
  const ceilings = [workspace, grant, ...(paths as string[][])].map((values) => new Set(values));
  if (requested.some((capability) => !ceilings.every((ceiling) => ceiling.has(capability)))) {
    return { verdict: "reject", reason_code: "capability_escalation" };
  }
  return {
    verdict: "accept",
    normalized: { effective_capabilities: requested },
  };
}

export type WorkspaceResourceKeySeparationInput = Readonly<{
  role_epoch_key_id: string;
  resources: readonly Readonly<{ resource_id: string; content_key_id: string }>[];
}>;

/** Validates that role MLS admission never doubles as a universal content key. */
export function evaluateWorkspaceResourceKeySeparation(
  input: WorkspaceResourceKeySeparationInput,
): WorkspacePolicyDecision {
  if (
    typeof input.role_epoch_key_id !== "string"
    || input.role_epoch_key_id.length === 0
    || !Array.isArray(input.resources)
    || input.resources.length === 0
    || input.resources.some(({ resource_id, content_key_id }) =>
      typeof resource_id !== "string" || resource_id.length === 0
      || typeof content_key_id !== "string" || content_key_id.length === 0)
    || new Set(input.resources.map(({ resource_id }) => resource_id)).size !== input.resources.length
  ) return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  const resourceKeys = input.resources.map(({ content_key_id }) => content_key_id);
  if (
    resourceKeys.includes(input.role_epoch_key_id)
    || new Set(resourceKeys).size !== resourceKeys.length
  ) return { verdict: "reject", reason_code: "capability_escalation" };
  return {
    verdict: "accept",
    normalized: {
      resource_key_ids: [...resourceKeys].sort(),
      role_key_used_as_content_key: false,
    },
  };
}

/** Evaluates the signed affiliation proof's temporal validity at effect time. */
export function evaluateWorkspaceAffiliationBoundary(input: Readonly<{
  now: number;
  observed_at: number;
  expires_at: number;
  maximum_age: number;
}>): WorkspacePolicyDecision {
  if (
    !Number.isSafeInteger(input.now)
    || !Number.isSafeInteger(input.observed_at)
    || !Number.isSafeInteger(input.expires_at)
    || !Number.isSafeInteger(input.maximum_age)
    || input.now < 0
    || input.observed_at < 0
    || input.expires_at < 0
    || input.maximum_age < 0
    || input.observed_at >= input.expires_at
  ) return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  if (
    input.observed_at > input.now
    || input.now >= input.expires_at
    || input.now - input.observed_at > input.maximum_age
  ) return { verdict: "reject", reason_code: "affiliation_stale" };
  return {
    verdict: "accept",
    normalized: { proof_age: input.now - input.observed_at },
  };
}

/** Enforces a single comparable predecessor, active device, and one-time invite. */
export function evaluateWorkspaceStateTransitionBoundary(input: Readonly<{
  prior_head: string;
  asserted_predecessor: string;
  device_active: boolean;
  invitation_nonce_unused: boolean;
}>): WorkspacePolicyDecision {
  if (
    typeof input.prior_head !== "string"
    || input.prior_head.length === 0
    || typeof input.asserted_predecessor !== "string"
    || input.asserted_predecessor.length === 0
    || typeof input.device_active !== "boolean"
    || typeof input.invitation_nonce_unused !== "boolean"
  ) return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  if (input.asserted_predecessor !== input.prior_head) {
    return { verdict: "reject", reason_code: "authority_conflict" };
  }
  if (!input.device_active) return { verdict: "reject", reason_code: "device_revoked" };
  if (!input.invitation_nonce_unused) {
    return { verdict: "reject", reason_code: "workspace_replay" };
  }
  return {
    verdict: "accept",
    normalized: { predecessor: input.prior_head, invitation_consumed: true },
  };
}

/** Applies current resource, custody-host, epoch, and history constraints. */
export function evaluateWorkspaceResourceDeliveryBoundary(input: Readonly<{
  resource_id: string;
  known_resource_ids: readonly string[];
  custody_host_id: string;
  authorized_custody_host_ids: readonly string[];
  requested_epoch: number;
  current_epoch: number;
  admission_epoch: number;
  history_mode: "full" | "from-admission" | "selected-snapshots";
  selected_snapshot_epochs?: readonly number[];
}>): WorkspacePolicyDecision {
  const stringSet = (values: readonly string[]): boolean =>
    Array.isArray(values)
    && values.length > 0
    && values.every((value) => typeof value === "string" && value.length > 0)
    && new Set(values).size === values.length;
  if (
    typeof input.resource_id !== "string"
    || input.resource_id.length === 0
    || typeof input.custody_host_id !== "string"
    || input.custody_host_id.length === 0
    || !stringSet(input.known_resource_ids)
    || !stringSet(input.authorized_custody_host_ids)
    || !Number.isSafeInteger(input.requested_epoch)
    || !Number.isSafeInteger(input.current_epoch)
    || !Number.isSafeInteger(input.admission_epoch)
    || input.requested_epoch < 0
    || input.current_epoch < 0
    || input.admission_epoch < 0
    || !["full", "from-admission", "selected-snapshots"].includes(input.history_mode)
    || input.selected_snapshot_epochs !== undefined
      && (!Array.isArray(input.selected_snapshot_epochs)
        || input.selected_snapshot_epochs.some((epoch) =>
          !Number.isSafeInteger(epoch) || epoch < 0)
        || new Set(input.selected_snapshot_epochs).size !== input.selected_snapshot_epochs.length)
  ) return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  if (
    !input.known_resource_ids.includes(input.resource_id)
    || input.requested_epoch > input.current_epoch
  ) return { verdict: "reject", reason_code: "resource_unknown" };
  if (!input.authorized_custody_host_ids.includes(input.custody_host_id)) {
    return { verdict: "reject", reason_code: "host_unauthorized" };
  }
  if (
    input.history_mode === "from-admission" && input.requested_epoch < input.admission_epoch
    || input.history_mode === "selected-snapshots"
      && !input.selected_snapshot_epochs?.includes(input.requested_epoch)
  ) return { verdict: "reject", reason_code: "history_denied" };
  return {
    verdict: "accept",
    normalized: {
      resource_id: input.resource_id,
      custody_host_id: input.custody_host_id,
      key_epoch: input.requested_epoch,
      history_mode: input.history_mode,
    },
  };
}
