import { describe, expect, it } from 'vitest';
import { fixtureData } from '../testing/pii-data.js';
import { isValidGs1CheckDigit } from './checksums.js';
import { PiiDataMissingError, PiiText } from './context.js';
import { findGs1Serial } from './gs1.js';
import type { PiiMatch } from './recognizers.js';

const GS = '\x1D';
// A GTIN-14 whose check digit holds, and the same with the last digit changed.
const GTIN = '08699999999994';
const BAD_GTIN = '08699999999995';

const data = fixtureData();

function run(text: string, strict = true, withData = true): string[] {
  const out: PiiMatch[] = [];
  findGs1Serial(new PiiText(text, withData ? data : undefined), strict, out);
  return out.map((m) => text.slice(m.start, m.end));
}

describe('GS1 check digit', () => {
  it('accepts a valid GTIN of any length and rejects a broken one', () => {
    expect(isValidGs1CheckDigit(GTIN)).toBe(true);
    expect(isValidGs1CheckDigit(BAD_GTIN)).toBe(false);
    expect(isValidGs1CheckDigit('4006381333931')).toBe(true); // a published EAN-13 example
    expect(isValidGs1CheckDigit('96385074')).toBe(true); // a published GTIN-8 example
    expect(isValidGs1CheckDigit('1234')).toBe(false);
    expect(isValidGs1CheckDigit('0869999999999A')).toBe(false);
  });
});

describe('findGs1Serial — human-readable form', () => {
  it('masks the whole run, batch and expiry included', () => {
    const text = `kutu (01)${GTIN}(21)ABC123XYZ456(17)261231(10)LOT7 satıldı`;

    expect(run(text)).toEqual([`(01)${GTIN}(21)ABC123XYZ456(17)261231(10)LOT7`]);
  });

  it('needs the serial: a GTIN alone, or with batch and expiry, is not masked', () => {
    expect(run(`(01)${GTIN}`)).toEqual([]);
    expect(run(`(01)${GTIN}(17)261231(10)LOT7`)).toEqual([]);
    expect(run('(10)LOT7(17)261231')).toEqual([]);
  });

  it('needs the GTIN: a serial without one is not masked', () => {
    expect(run('(21)ABC123XYZ456')).toEqual([]);
  });

  it('reads the AIs in any order', () => {
    expect(run(`(21)SER1234(01)${GTIN}`)).toEqual([`(21)SER1234(01)${GTIN}`]);
  });

  it('holds the check digit in the strict mode, and in the loose one unless a keyword sits beside it', () => {
    const run1 = `(01)${BAD_GTIN}(21)SER1234`;

    expect(run(run1)).toEqual([]);
    expect(run(`karekod ${run1}`)).toEqual([]);
    // The loose mode is the base recognisers' trade: a keyword rescues a wrong check digit, nothing else does.
    expect(run(run1, false)).toEqual([]);
    expect(run(`ürün ${run1}`, false)).toEqual([]);
    expect(run(`karekod ${run1}`, false)).toEqual([run1]);
    expect(run(`${run1} (UDI)`, false)).toEqual([run1]);
    // A valid GTIN needs no keyword in either mode, and so no data.
    expect(run(`(01)${GTIN}(21)SER1234`, false, false)).toEqual([`(01)${GTIN}(21)SER1234`]);
  });

  it('needs the ruleset data to rescue a wrong check digit, and says so', () => {
    expect(() => run(`(01)${BAD_GTIN}(21)SER1234`, false, false)).toThrow(PiiDataMissingError);
  });

  it('reads a single space after a closing parenthesis and between groups', () => {
    const spaced = `(01) ${GTIN} (21) J06EJWW9GK2 (17) 271010`;

    expect(run(`ekran: ${spaced} tamam`)).toEqual([spaced]);
    expect(run(`(01) ${GTIN}`)).toEqual([]);
    // Two spaces end the run.
    expect(run(`(01) ${GTIN}  (21) J06EJWW9GK2`)).toEqual([]);
  });

  it('stops at a malformed group', () => {
    expect(run(`(01)${GTIN}(21)SER1234(17)26123X rest`)).toEqual([`(01)${GTIN}(21)SER1234`]);
    expect(run('(01)1234(21)SER1234')).toEqual([]);
    expect(run(`(01)${GTIN}(99)zz(21)SER1234`)).toEqual([]);
    expect(run(`(01)${GTIN}(21)`)).toEqual([]);
  });

  it('does not run on past a second run', () => {
    expect(run(`(01)${GTIN}(21)A1 and (01)${GTIN}(21)B2`)).toEqual([
      `(01)${GTIN}(21)A1`,
      `(01)${GTIN}(21)B2`,
    ]);
  });
});

describe('findGs1Serial — raw data-carrier form', () => {
  it('reads GTIN, serial, expiry and batch separated by GS', () => {
    const raw = `01${GTIN}21SER1234567${GS}17261231${GS}10LOT7`;

    expect(run(`scan ${raw} done`)).toEqual([raw]);
  });

  it('reads a run with no GS where the scanner dropped them', () => {
    const raw = `01${GTIN}21SER123456717261231`;

    expect(run(`scan ${raw} done`)).toEqual([raw]);
  });

  it('reads expiry before the serial, and a GS after a fixed field', () => {
    const raw = `01${GTIN}17261231${GS}21SER1234`;

    expect(run(raw)).toEqual([raw]);
  });

  it('needs the serial, the GTIN check digit and a boundary before the 01', () => {
    expect(run(`01${GTIN}`)).toEqual([]);
    expect(run(`01${GTIN}17261231`)).toEqual([]);
    expect(run(`01${GTIN}21`)).toEqual([]);
    expect(run(`01${BAD_GTIN}21SER1234`)).toEqual([]);
    expect(run(`01${BAD_GTIN}21SER1234`, false)).toEqual([]);
    expect(run(`lot 01${BAD_GTIN}21SER1234`, false)).toEqual([`01${BAD_GTIN}21SER1234`]);
    expect(run(`9901${GTIN}21SER1234`)).toEqual([]);
  });

  it('reads a symbology identifier before the GTIN and a space after it', () => {
    expect(run(`]d201${GTIN}21J06EJWW9GK2`)).toEqual([`01${GTIN}21J06EJWW9GK2`]);
    expect(run(`]C101${GTIN} 21J06EJWW9GK2 17271010`)).toEqual([
      `01${GTIN} 21J06EJWW9GK2 17271010`,
    ]);
    expect(run(`]Q301${GTIN}21J06EJWW9GK2`)).toEqual([`01${GTIN}21J06EJWW9GK2`]);
    expect(run(`]x201${GTIN}21J06EJWW9GK2`)).toEqual([]);
  });

  it('lets a space continue a run only before a date AI, never before a word', () => {
    expect(run(`01${GTIN}21SER1234 17261231`)).toEqual([`01${GTIN}21SER1234 17261231`]);
    expect(run(`01${GTIN}21SER1234 10days later`)).toEqual([`01${GTIN}21SER1234`]);
  });

  it('does not take a retail EAN-13 for a pack identifier', () => {
    expect(run('Barkod: 8690123456785')).toEqual([]);
  });
});
