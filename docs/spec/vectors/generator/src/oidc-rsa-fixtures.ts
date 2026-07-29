import { computeJwkThumbprint, type JsonValue } from "./claims.js";

const RAW_ONE = {
  kty: "RSA", n: "zvh2fntchh51kVXPblIG2eeggjb0bya6jHF5xOsHTUhr8bi01jmbNjP29oPeFyoztGGKpndDxqt9qHvOL5x3euFKrm6kZywZ_XDVfdZVm7icnpybEmNdammqZcf97EIwOr_mczhRZ9QYK7SsSnBEQW1-BAs9dEHxNT39VqHjCq81uhzLKeemrpW4Kim_s4iYmoRoVkiPHghPhGo9CKXNXj2tGyDmj5hwuXa_gv5sZu5C7u0L9y4T25a-VHFVyUnCoa1yhyiT3teW3256KPmA6rBz1YhdLOCnwWDqIaBGOe4J6gkIODNCuCHwtI8JnX3gcRni_Pz19f3SNqtEJMvWjw", e: "AQAB",
  d: "P5h-BIBQXk-2rWkyG0JuI3-2RLyxIARE9wmZMoZLUJZrwLMSMe8yf5W5EWdUk0ae65K7QUpNU5r3OhGMufl4hxP52B5cOu2EsOj-WLPGy1oPGfeh-KT6m8uLFco9fl6aJjs4CvhnnyE_KhLSi-7yMi58Na7ke7gVb1g0Y23L70h4mOXAImpPwUp_0nfeAelfyMvGyzZ5uTBUNQM-AbtrnKBCXUwws-UjewFKiQsvQjw4nZgH17iVnbMFElWVT9sk2xOmDujDl8_Ewb9Zjd1azOH9eCjZkr_JAOHzfu85Cqix4Aqqp4B78_gU1qwq69QiKjdgHxHUB_8CxjLa3KzDZQ",
  p: "66Wvrwj9QlOEZJYqKz7IUS-15_Y807PqFMzOEobId5LHJyKsDNSfxp0EWW1LOQmBNnPwXJm9n9bHkQbCfTwheVehY9hX1sA7tesq7f5-5KdS8IDGe1qHE8no4iPfe83H8DM7YteFWF8gbR59IJpYfXRvTk9a7zjyGWGzuQBHKvs", q: "4Ni3kTJiJh6xOwFMhFH6LrBlB7006lWrUKyE2DMrDJuVJenUdKN_4jdjRS_IkRIPQC9Wv40hqz69J0XuxPSoVm5ns2Y46yHBzK8HmPB6ltg1AzYqsc4Pq4pBaB53WA4XdiG1mp7i_1l4MEb9u-72zsqvrJqkE__7w6XNNBR8bn0", dp: "dWtJ7137VGFpRvXMbWALUOkFK2B3TsYHjfW_eVvP6EUrF0UflgUc2ErFMApVwUYLLKb4ziuNYWgUaR-FKgIca-pOcQIMQuXm2u8jpRN7B1SY7147iJvDUwj5EjXt1jLjvbzJiqb5ut8ruTPIBcbi8SBjlhHUrf8iI6ObekO5MqE", dq: "nTbrI5sXBZBwW9GMrvii9gJgogip9y_vmXkHaiRc9XPT1a6p3uRzhrkzsCy5ELaP81EmVslXwWUc3VkImq53BfgsikPviHkSCQxZQ5biIJcMejJlp-1tB4SkNykWSXuQ7Ail8ncmQWVNpHP-9mkgKXePXiDCmTlj0GkeEkxAtQ", qi: "VKMYvlDjM_Egmzs2h1BDzQaiDHRfKWdBBB6KYqyIodnPbveXy3ZFJMdehBNEx3OJYzcEV501JyxUJBTvr9dCakZt-R5ZYrDrQLT3u-9P_Egblnn8HxBRBrrNkYbhdXQZovahuQEg3My6LxgwfMZGPgHyKLZZilBFVn4jnU-eVAY",
};

const RAW_TWO = {
  kty: "RSA", n: "ug8ZrjW_GrLuEl86Vp0nvyyS8HlbGjhrNhzps9sWoTeCs-xUFx7MDRobDx2DEgdvsDmothFYHUTCYaYEeUUiJaCxt1YjAif4uIDwTCG_gySLyMwnvnn3v4ZNuUJvD5_6u6Myx-fs7lo9HXCQh7KkvlFXj0kI5zh9ukatZzRc3ajIVCEvpJdB5oO0QkDmO-RgAcQyz2ZMxNNCdraeR2PN_0XPiEeDy_FX1gDZebftHAB1W0DB0puytYtPzgdGaVVqerYRaEeuHXhH7KH0XfZa6nxILMZ5oMcPJ7VnIgmpOtVw-NOeYjnfHdEDqnm05CG7d2Wm292lpBL0lm8_mJkodw", e: "AQAB",
  d: "XBUrHYgmG52gq-ELa2B-EmSKGI_HIdP4Y6CtnUD6EzH48vksqQCp9nYMHE_71YluomX29Jzi4iFsno1eu3IWs06zhcwQqXmE5DOUOemd8da9g9Reeyu8DML4Zo7VjoMbwY_EiyFipphslMxoC3DDjhmN3zFDQcQ4nV9rZJ-KsnyEbfmz4vmpqwRAje9NaqYI7idHBlyawvpvsNxzzImQICHx69vf-q1xcwbiNqu-DBmlcQ5G180eOntu_VbrzwxkeO2LHUyi-r680n6x_t6SssHkx5qJkKPNucrpWMkQw4k7MIoXLOskicdbyI3p0aHACMfZH-QDq1LR0meVbtq-qQ",
  p: "7CVfHoiCcxcRoZatVWSuSZSEaN75fJTiuRxuU5Nvr-Ujs2wrnJ3V5VO_fc9MG_cUnR1Y1ZD1y-qNSZF4AerOPrCtqtOutOjbD-fPAkHLW9-RrjdbG2l0Yu6ViBP-kGv9HJypxL6ul2OCRI77GTQuZJ8zbjGn_raAL17GW6soXiM", q: "ybOxpKiVO6Ev41gUoem5WL9pHxy60N6MZX5l9pMb8mUI1DuB_xs_iibS06FodPduHAzpBVCvGKeCY6YH1dzF9BR1_58OruB6550uRrsvjcONw1wh8t-2AerfBAzlSVfo7BNRyBfhTJkip0Wo6P35Lra7Zbn2WyO6rsLKCHmlL50", dp: "jMzrniT-wuiqVpKk3xmc4bpwCKeKUkHjvUO6dJKgMVyKoNyKVGO3uXjp4HXNh48W92ccJJq-M8uyWn8l8t6yAqcNpaF5tdxxYVZyE4JvYmQ3VI0lAX8rKiHffreNPUdmL70pbGnVZ-apMX-fMDPwxYY3ACkTZcgjPhtgYh_3fck", dq: "GfdlNjJxy9RratQrC9EgCFnT-apkLoGIB4TnMYAsx97T7SagDKyAWJO47n_IB87WwQu0b_e8IutlsNhuB809OrfrnPXoGQFTMUAd9gMhExoKxQy2XiMItmR7Q3U5i2Ci3sl57M2ONqM8P9aK8TvI-YeSxnzTR1ZpMRholAC9EE0", qi: "JWlEkXbpADqqNwEl7ODyWKMHLGiwVWf6Y-JcuR4Ly0PKp25LoyfFiap06HU1OSyUZWZu_OmDaPcHgQUmWrN2YkjHBwOIVZFwRUr2xDtwM1k4cNcITgAHVytpYpTsU8elUBGH8D23WbOakcCFfZJ12P53neL5DXExqjQgxMpc0C0",
};

function pair(raw: typeof RAW_ONE): { private_jwk: Record<string, JsonValue>; public_jwk: Record<string, JsonValue>; key_id: string } {
  const public_jwk: Record<string, JsonValue> = { kty: "RSA", n: raw.n, e: raw.e };
  const key_id = computeJwkThumbprint(public_jwk);
  return {
    key_id,
    private_jwk: { ...raw, kid: key_id, alg: "RS256", use: "sig", key_ops: ["sign"] },
    public_jwk: { ...public_jwk, kid: key_id, alg: "RS256", use: "sig", key_ops: ["verify"] },
  };
}

export const OIDC_RSA_ONE = pair(RAW_ONE);
export const OIDC_RSA_TWO = pair(RAW_TWO as typeof RAW_ONE);
