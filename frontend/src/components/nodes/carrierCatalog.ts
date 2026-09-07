import type { CarrierLineBinding, CarrierLineCatalogItem } from '../../api/types';

export function assignCarrierLines(bindings: CarrierLineBinding[], nodeId: string, selected: string[]): CarrierLineBinding[] {
  const selectedSet = new Set(selected);
  const next = bindings.filter((binding) => binding.node_id !== nodeId && !selectedSet.has(binding.line_id));
  next.push(...selected.map((lineId) => ({ line_id: lineId, mode: 'node' as const, node_id: nodeId })));
  return next.sort((left, right) => left.line_id < right.line_id ? -1 : left.line_id > right.line_id ? 1 : 0);
}

export interface CatalogTreeNode {
  value: string;
  title: string;
  children?: CatalogTreeNode[];
}

export function buildCarrierCatalogTree(lines: CarrierLineCatalogItem[]): CatalogTreeNode[] {
  const byId = new Map(lines.map((line) => [line.id, line]));
  const children = new Map<string, CarrierLineCatalogItem[]>();
  const roots: CarrierLineCatalogItem[] = [];
  for (const line of lines) {
    if (line.parent && line.parent !== line.id && byId.has(line.parent)) {
      children.set(line.parent, [...(children.get(line.parent) ?? []), line]);
    } else {
      roots.push(line);
    }
  }
  const build = (line: CarrierLineCatalogItem, ancestors: Set<string>): CatalogTreeNode => {
    const nextAncestors = new Set(ancestors).add(line.id);
    const nested = (children.get(line.id) ?? [])
      .filter((child) => !nextAncestors.has(child.id))
      .sort((left, right) => left.name.localeCompare(right.name))
      .map((child) => build(child, nextAncestors));
    return {
      value: line.id,
      title: line.name || line.id,
      ...(nested.length > 0 ? { children: nested } : {}),
    };
  };
  return roots
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((line) => build(line, new Set()));
}
