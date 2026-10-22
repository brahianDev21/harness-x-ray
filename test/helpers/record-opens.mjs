// Records the paths that the code under test opens for reading. The target readers open files with openSync and read them
// with readFileSync, both on the node:fs default object, so the recorder wraps those two. Stats are not recorded: the walk
// over the parent folders stats their files by design. The wrappers are mocks of the test, and t.mock restores them when
// the test ends.

import fs from "node:fs";
import path from "node:path";

/**
 * Starts recording the opened paths, in call order.
 * @param {import("node:test").TestContext} t The test whose mocks are restored at its end.
 * @returns {string[]} The array that fills as the code opens files.
 */
export function recordOpens(t) {
  const opened = [];
  const realOpen = fs.openSync;
  const realRead = fs.readFileSync;
  t.mock.method(fs, "openSync", (file, ...rest) => {
    opened.push(String(file));
    return realOpen(file, ...rest);
  });
  t.mock.method(fs, "readFileSync", (file, ...rest) => {
    opened.push(String(file));
    return realRead(file, ...rest);
  });
  return opened;
}

/** Whether a path is the folder itself or lies inside it. Both paths must be real paths for the answer to hold. */
export function within(folder, file) {
  const rel = path.relative(folder, file);
  return rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}
