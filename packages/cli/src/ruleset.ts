/**
 * Loading the ruleset the scanner runs against.
 *
 * The CLI reads the ruleset data from `@mcpguard/ruleset` and hands it to the
 * engine's `loadRuleset`, which validates, digests and compiles it. The engine
 * is the one authority on whether the data is a valid ruleset, so nothing is
 * checked twice.
 */
import { type CompiledRuleset, loadRuleset } from '@mcpguard/detect';
import { loadRulesetData } from '@mcpguard/ruleset';
import { CliError, EXIT } from './errors.js';

/** Loads and compiles the shipped ruleset. */
export function loadShippedRuleset(): CompiledRuleset {
  try {
    return loadRuleset(loadRulesetData());
  } catch (error) {
    throw new CliError(`the ruleset failed to load: ${(error as Error).message}`, {
      exitCode: EXIT.ruleset,
    });
  }
}
