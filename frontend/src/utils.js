import { DETECTORS_CONFIG } from "./config";

export function formatAttackType(type) {
  const item = DETECTORS_CONFIG.find((d) => d.type === type);
  return item ? item.label : type;
}
