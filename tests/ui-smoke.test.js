import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("ui shell includes filters and result host", async () => {
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");

  assert.match(html, /id="search-input"/);
  assert.match(html, /id="category-filter"/);
  assert.match(html, /id="layer-filter"/);
  assert.match(html, /id="results"/);
});

test("ui script includes warning and unknown filters", async () => {
  const script = await readFile(new URL("../src/main.js", import.meta.url), "utf8");

  assert.match(script, /unknownOnlyToggle/);
  assert.match(script, /warningOnlyToggle/);
  assert.match(script, /Alternative interpretations/);
});
