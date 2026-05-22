import test from "node:test";
import assert from "node:assert/strict";

import { COMMAND_DEFINITIONS, matchCommand, listSupportedCommands } from "../src/apdu-registry.js";
import { parseCommandApdu } from "../src/iso7816/apdu-structure.js";

test("lists commands from all protocol layers", () => {
  const commands = listSupportedCommands();
  const names = commands.map((command) => command.name);
  const layers = new Set(commands.map((command) => command.layer));

  assert.ok(names.includes("SELECT FILE"));
  assert.ok(names.includes("TERMINAL PROFILE"));
  assert.ok(names.includes("INSTALL"));
  assert.ok(names.includes("MANAGE LSI"));
  assert.ok(layers.has("ISO 7816-4 APDU layer"));
  assert.ok(layers.has("GlobalPlatform card management layer"));
});

test("contextual matching prefers GlobalPlatform GET STATUS over ISO STATUS on proprietary CLA", () => {
  const apdu = parseCommandApdu([0x80, 0xf2, 0x40, 0x00, 0x02, 0x4f, 0x00, 0x00]);
  assert.equal(apdu.ok, true);

  const matched = matchCommand(apdu);
  assert.equal(matched.best.command.name, "GET STATUS");
  assert.equal(matched.best.command.layer, "GlobalPlatform card management layer");
});

test("contextual matching preserves ISO STATUS on interindustry CLA", () => {
  const apdu = parseCommandApdu([0x00, 0xf2, 0x00, 0x00, 0x10]);
  assert.equal(apdu.ok, true);

  const matched = matchCommand(apdu);
  assert.equal(matched.best.command.name, "STATUS");
  assert.equal(matched.best.command.layer, "ETSI TS 102 221 UICC layer");
});

test("registry contains a real layered catalog rather than a tiny flat list", () => {
  assert.ok(COMMAND_DEFINITIONS.length >= 20);
});
