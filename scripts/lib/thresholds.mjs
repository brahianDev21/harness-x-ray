// The thresholds of the measured rules. Only the values that the rule texts cite live here, so the emitters
// (measured-findings.mjs) and the structure measure read the same numbers. This module has no imports, so any
// module can import it without a cycle.
//
// Every value starts provisional. None is measured: each is an assumption, derived as the comment says. A value
// changes only with the evidence that scripts/calibrate.mjs writes (the distribution of each measure over a sample
// of repositories, see lib/calibration.mjs and the calibration document). When a value changes on that evidence, its
// status in THRESHOLDS_STATUS becomes "calibrated" in the same change. The report states the status next to every
// threshold it cites, by key, using THRESHOLDS_STATUS.

/**
 * The status of every value in THRESHOLDS, by key: "provisional" (an assumption) or "calibrated" (changed on the
 * evidence of a calibration). Frozen, with the same keys as THRESHOLDS.
 */
export const THRESHOLDS_STATUS = Object.freeze({
  memoryFileMaxLines: "provisional",
  alwaysLoadedTokensMedium: "provisional",
  alwaysLoadedTokensHigh: "provisional",
  skillDescriptionMaxChars: "provisional",
  skillCountMax: "provisional",
  largeFileBytes: "provisional",
  duplicationPctMedium: "provisional",
  duplicationPctHigh: "provisional",
});

export const THRESHOLDS = Object.freeze({
  // CTX-01. An always-loaded memory file above this many lines. From the size target of the memory documentation
  // ("target under 200 lines per CLAUDE.md file").
  memoryFileMaxLines: 200,
  // CTX-01. Y, the medium level of the always-loaded budget, in estimated tokens. Derivation: 200 lines x about 60
  // characters per line / 4 characters per token = 3,000. The 60 characters per line is an assumption.
  alwaysLoadedTokensMedium: 3000,
  // CTX-01. X, the high level of the always-loaded budget, in estimated tokens. X = 2 x Y, a choice of the rule.
  alwaysLoadedTokensHigh: 6000,
  // CTX-04. A skill whose listed description (description and when_to_use) is longer than this many characters is long. The
  // skill listing cuts a description at 1,536 characters (docs: skills), which a description past the cut always triggers;
  // 1,024 is two thirds of that cut, so a long description is flagged while it still has room before it. At chars/4, 1,024
  // characters are about 256 estimated tokens that load in every session for one skill. An assumption.
  skillDescriptionMaxChars: 1024,
  // CTX-04. More skills in the listing than this is a high count. Derivation: Y (alwaysLoadedTokensMedium, 3,000 tokens)
  // divided by 100 estimated tokens per listing entry (an assumed description of about 400 characters) = 30, the count at
  // which the listing alone would reach Y. An assumption.
  skillCountMax: 30,
  // STR-02. A versioned file above this many bytes counts as large. The Read tool refuses a whole-file read above
  // 256 KB, so such a file cannot be read in one call. The value is taken from that limit.
  largeFileBytes: 262144,
  // COD-01. Share of redundant lines, in percent, above which the duplication finding is medium. An assumption:
  // a reviewer would notice repeated blocks in a project of a few thousand normalized lines.
  duplicationPctMedium: 5,
  // COD-01. Share, in percent, above which the duplication finding is high ("far above"). Three times the medium level.
  duplicationPctHigh: 15,
});
