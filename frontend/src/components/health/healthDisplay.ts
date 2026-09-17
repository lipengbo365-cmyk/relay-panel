export function resourceDisplayName(id: number, names: ReadonlyMap<number, string>): string {
  return names.get(id) ?? `Resource #${id}`;
}
export function nodeDisplayName(id: number, names: ReadonlyMap<number, string>): string {
  return names.get(id) ?? `Node #${id}`;
}
