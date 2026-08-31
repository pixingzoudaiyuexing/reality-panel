import type { CarrierLineCatalogItem } from '../../api/types';

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
