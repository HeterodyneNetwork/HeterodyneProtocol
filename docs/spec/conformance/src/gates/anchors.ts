export type SpecificationOwner = "core" | "comms" | "control" | "social" | "workspace";

const owners: readonly SpecificationOwner[] = [
  "core",
  "comms",
  "control",
  "social",
  "workspace",
];

export function extractExplicitAnchors(specification: string): ReadonlySet<string> {
  const anchors = new Set<string>();
  const anchorPattern = /<a\b[^>]*\bid\s*=\s*(["'])([^"'<>]+)\1[^>]*>/giu;
  for (const match of specification.matchAll(anchorPattern)) {
    anchors.add(match[2]);
  }
  return anchors;
}

export function ownerForAnchor(anchor: string): SpecificationOwner | undefined {
  return owners.find((owner) => anchor.startsWith(`${owner}-`));
}

export function ownerForSpecificationPath(path: string): SpecificationOwner | undefined {
  return owners.find((owner) => path === `docs/spec/heterodyne-${owner}.md`);
}
