declare const PRIVATE_CURRENT_FIXTURE_SPECIFICATION: unique symbol;

export type PrivateCurrentFixtureSpecification = Readonly<{
  readonly [PRIVATE_CURRENT_FIXTURE_SPECIFICATION]: true;
}>;

type SpecificationRecord = Readonly<{
  ids: ReadonlySet<string>;
}>;

const SPECIFICATIONS = new WeakMap<object, SpecificationRecord>();
const DECLARED_PRIVATE_CURRENT_FIXTURE_IDS = new Set<string>();

/** Defines the closed, family-owned allowlist that is also required at registration. */
export function definePrivateCurrentFixtureSpecification(
  caseIds: readonly string[],
): PrivateCurrentFixtureSpecification {
  const ids = new Set(caseIds);
  if (ids.size === 0 || ids.size !== caseIds.length) {
    throw new Error("private current fixture specification must be non-empty and unique");
  }
  for (const caseId of ids) {
    if (caseId.length === 0 || DECLARED_PRIVATE_CURRENT_FIXTURE_IDS.has(caseId)) {
      throw new Error(`duplicate private current fixture specification: ${caseId}`);
    }
  }
  const specification = Object.freeze({}) as PrivateCurrentFixtureSpecification;
  SPECIFICATIONS.set(specification, { ids });
  for (const caseId of ids) DECLARED_PRIVATE_CURRENT_FIXTURE_IDS.add(caseId);
  return specification;
}

function specificationRecord(
  specification: PrivateCurrentFixtureSpecification,
): SpecificationRecord {
  const record = SPECIFICATIONS.get(specification);
  if (record === undefined) throw new Error("unknown private current fixture specification");
  return record;
}

export function registerPrivateCurrentFixtureSpecificationId(
  specification: PrivateCurrentFixtureSpecification,
  caseId: string,
): void {
  const record = specificationRecord(specification);
  if (!record.ids.has(caseId)) {
    throw new Error(`private current fixture is outside its family specification: ${caseId}`);
  }
}

export function isDeclaredPrivateCurrentFixtureId(caseId: string): boolean {
  return DECLARED_PRIVATE_CURRENT_FIXTURE_IDS.has(caseId);
}

/** Non-authoritative diagnostics used to assert declaration/registration equality. */
export function declaredPrivateCurrentFixtureIds(): readonly string[] {
  return Object.freeze([...DECLARED_PRIVATE_CURRENT_FIXTURE_IDS].sort((left, right) =>
    left.localeCompare(right, "en")
  ));
}
