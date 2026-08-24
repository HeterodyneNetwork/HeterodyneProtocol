export type SpecificationOwner =
  | "core" | "assurance" | "comms" | "control" | "social" | "workspace";

const owners: readonly SpecificationOwner[] = [
  "core",
  "assurance",
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

export type SpecificationReference = {
  owner: SpecificationOwner;
  anchor: string;
};

export function parseSpecificationReference(reference: string): SpecificationReference | undefined {
  const match = /^heterodyne:(core|assurance|comms|control|social|workspace)#([a-z0-9][a-z0-9-]*)$/u
    .exec(reference);
  return match === null
    ? undefined
    : { owner: match[1] as SpecificationOwner, anchor: match[2]! };
}

export function formatSpecificationReference(
  owner: SpecificationOwner,
  anchor: string,
): string {
  return `heterodyne:${owner}#${anchor}`;
}

export function ownerForSpecificationPath(path: string): SpecificationOwner | undefined {
  return owners.find((owner) => path === `docs/spec/heterodyne-${owner}.md`);
}
