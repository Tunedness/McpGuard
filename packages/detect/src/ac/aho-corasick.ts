/**
 * Aho–Corasick multi-pattern matching.
 *
 * This is the single biggest reason the latency budget is reachable. A ruleset
 * is data and grows; the naive shape — loop over every rule's regex on every
 * scan — is linear in the rule count, so a ruleset at version 1.2 would cost
 * more than one at 1.0 for no reason a user could see. One automaton finds every
 * literal in a single pass over the text, and the cost is the text's length, not
 * the ruleset's.
 *
 * Built once, when the ruleset is compiled. Matching allocates nothing but the
 * result list and never mutates the automaton, so concurrent scans share one.
 */

/** One literal the automaton was built to find, with the id that owns it. */
export interface Term {
  readonly id: string;
  /** The literal, already folded to the surface it will be matched against. */
  readonly value: string;
}

/** Where a term was found. Offsets are into the searched string. */
export interface Match {
  readonly id: string;
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

interface Node {
  /** Next node per character code. Sparse; most nodes have a handful of edges. */
  readonly next: Map<number, number>;
  /** Suffix link, the fall-back node when the current character does not match. */
  fail: number;
  /** Term indices that end at this node, plus those reachable by output links. */
  outputs: number[];
}

/** A compiled automaton. Immutable after {@link buildAutomaton}. */
export interface Automaton {
  readonly nodes: readonly Node[];
  readonly terms: readonly Term[];
}

/** Builds the automaton for a set of terms. Empty terms are dropped. */
export function buildAutomaton(terms: readonly Term[]): Automaton {
  const kept = terms.filter((term) => term.value.length > 0);
  const nodes: Node[] = [{ next: new Map(), fail: 0, outputs: [] }];

  // Trie insertion.
  kept.forEach((term, index) => {
    let node = 0;
    for (const code of codePoints(term.value)) {
      let child = nodes[node]?.next.get(code);
      if (child === undefined) {
        child = nodes.length;
        nodes.push({ next: new Map(), fail: 0, outputs: [] });
        nodes[node]?.next.set(code, child);
      }
      node = child;
    }
    nodes[node]?.outputs.push(index);
  });

  // Breadth-first fail links, the classic construction.
  const queue: number[] = [];
  const root = nodes[0];
  if (root !== undefined) {
    for (const child of root.next.values()) {
      const node = nodes[child];
      if (node !== undefined) node.fail = 0;
      queue.push(child);
    }
  }
  for (let head = 0; head < queue.length; head++) {
    const current = queue[head];
    if (current === undefined) continue;
    const node = nodes[current];
    if (node === undefined) continue;
    for (const [code, child] of node.next) {
      queue.push(child);
      let fail = node.fail;
      while (fail !== 0 && !nodes[fail]?.next.has(code)) {
        fail = nodes[fail]?.fail ?? 0;
      }
      const target = nodes[fail]?.next.get(code);
      const childNode = nodes[child];
      if (childNode === undefined) continue;
      childNode.fail = target !== undefined && target !== child ? target : 0;
      // Output links: a node inherits the outputs of the node its fail link
      // points at, so one walk collects every term that ends here.
      const failOutputs = nodes[childNode.fail]?.outputs ?? [];
      if (failOutputs.length > 0) childNode.outputs = [...childNode.outputs, ...failOutputs];
    }
  }

  return { nodes, terms: kept };
}

/**
 * Finds every term in `text`, in one pass.
 *
 * Offsets are code-point aware: `start`/`end` index into `text` by UTF-16 code
 * unit, so a span lands where a caller can slice it.
 */
export function search(automaton: Automaton, text: string): Match[] {
  const matches: Match[] = [];
  const { nodes, terms } = automaton;
  let node = 0;
  let unit = 0;
  for (const code of codePoints(text)) {
    const width = code > 0xffff ? 2 : 1;
    while (node !== 0 && !nodes[node]?.next.has(code)) {
      node = nodes[node]?.fail ?? 0;
    }
    node = nodes[node]?.next.get(code) ?? 0;
    const outputs = nodes[node]?.outputs;
    if (outputs !== undefined) {
      for (const termIndex of outputs) {
        const term = terms[termIndex];
        if (term === undefined) continue;
        const end = unit + width;
        matches.push({ id: term.id, value: term.value, start: end - term.value.length, end });
      }
    }
    unit += width;
  }
  return matches;
}

function* codePoints(text: string): Generator<number> {
  for (const char of text) {
    yield char.codePointAt(0) ?? 0;
  }
}
