import { type Registry, type RegisteredKindProfile, } from "../registry.js";
import type { CurrentProfileWireProbe } from "../profile-negotiation.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
export function buildProfileCases(registry: Registry): CurrentCaseFixture[] {
    return registry.kinds.flatMap(({ kind, profiles }) => profiles.map((profile) => {
        const candidate: RegisteredKindProfile = { kind, ...profile };
        const discriminator = profile.discriminator;
        const wireProbe: CurrentProfileWireProbe = discriminator.startsWith("content.profile=")
            ? {
                content_is_heterodyne_json: true,
                is_dr_outer: false,
                content_profile: discriminator.slice("content.profile=".length),
            }
            : discriminator.startsWith("tag:")
                ? (() => {
                    const allocation = discriminator.slice("tag:".length);
                    const separator = allocation.indexOf("=");
                    return {
                        content_is_heterodyne_json: false,
                        is_dr_outer: false,
                        tags: [[allocation.slice(0, separator), allocation.slice(separator + 1)]],
                    };
                })()
                : discriminator.startsWith("tags:L=")
                    ? (() => {
                        const namespace = /^tags:L=([^,]+),/u.exec(discriminator)?.[1];
                        if (namespace === undefined)
                            throw new Error(`invalid profile discriminator: ${discriminator}`);
                        return {
                            content_is_heterodyne_json: false,
                            is_dr_outer: false,
                            tags: [["L", namespace], ["l", `policy-denied@${namespace}`]],
                        };
                    })()
                    : discriminator.startsWith("production-rule:")
                        ? {
                            content_is_heterodyne_json: false,
                            is_dr_outer: false,
                            production_rule: discriminator.slice("production-rule:".length),
                        }
                        : discriminator === "marmot-inner-only;content=control-frame-v1"
                            ? {
                                content_is_heterodyne_json: true,
                                is_dr_outer: false,
                                transport: "marmot-inner",
                                content_profile_id: "control-frame-v1",
                            }
                            : (() => {
                                throw new Error(`unsupported profile discriminator: ${discriminator}`);
                            })();
        return {
            vector_id: `${profile.owner}/profile-${profile.profile_id}`,
            description: `The complete kind/profile allocation tuple for ${profile.profile_id} validates without inference.`,
            direction: "consume" as const,
            input: { ...candidate, wire_probe: wireProbe }
        };
    }));
}
