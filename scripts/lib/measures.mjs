// The list of measures of a scan. scan.mjs (the scan command) and ci.mjs (the CI mode) both build their list here, so the two
// commands run the same measures for the same flags. This module only chooses and orders the measures: each one is defined in
// its own module of lib/, and nothing here reads the target.

import { agentInventoryMeasure } from "./agent-inventory.mjs";
import { claudeConfigMeasure } from "./claude-config.mjs";
import { createDestructiveCommandsMeasure, destructiveCommandsMeasure } from "./destructive-commands.mjs";
import { DEEP_DUPLICATION_OPTIONS, createDuplicationMeasure, duplicationMeasure } from "./duplication.mjs";
import { injectionMeasure } from "./injection.mjs";
import { createLayerContextMeasure } from "./layer-context.mjs";
import { createMemoryMeasure, memoryMeasure } from "./memory.mjs";
import { referencesMeasure } from "./references.mjs";
import { secretsMeasure } from "./secrets.mjs";
import { structureMeasure } from "./structure.mjs";
import { createUserLayerMeasure } from "./user-layer.mjs";
import { verificationMeasure } from "./verification.mjs";

// The measures, in the order they run, for the given flags. Each measure adds its import and one line here. The references,
// verification and structure measures read the memory texts, so they run after the memory measure. The user layer runs right
// after the project configuration, because the permission measures read the rules it adds to ctx.outside. The agent-harness
// measure runs right after the memory measure: it reads the files of the other agents, and it needs neither the memory texts
// nor the output of the measures that follow it. The layer-context measure runs after the agent-harness measure, and only with
// a layer plan: it reads the memory files and rules that the memory measure has already read. The depth changes only the
// duplication and destructive-commands measures: deep gives them the settings or the matrix locations of its own.
export function measuresFor({ userLayer, ancestors, layers, depth }) {
  const memory = ancestors ? createMemoryMeasure({ includeAncestors: true }) : memoryMeasure;
  const deep = depth === "deep";
  return [
    claudeConfigMeasure,
    ...(userLayer ? [createUserLayerMeasure()] : []),
    memory,
    agentInventoryMeasure,
    ...(layers === undefined ? [] : [createLayerContextMeasure({ layers })]),
    referencesMeasure,
    verificationMeasure,
    deep ? createDestructiveCommandsMeasure({ deep: true }) : destructiveCommandsMeasure,
    secretsMeasure,
    injectionMeasure,
    structureMeasure,
    deep ? createDuplicationMeasure(DEEP_DUPLICATION_OPTIONS) : duplicationMeasure,
  ];
}
