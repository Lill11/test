import { parseApduText } from "./apdu-parser.js";
import { listSupportedCommands } from "./apdu-registry.js";
import { sampleInput } from "./ui/sample-apdus.js";

const input = document.querySelector("#apdu-input");
const resultsHost = document.querySelector("#results");
const summary = document.querySelector("#summary");
const supportedCommandsList = document.querySelector("#supported-commands");
const searchInput = document.querySelector("#search-input");
const categoryFilter = document.querySelector("#category-filter");
const layerFilter = document.querySelector("#layer-filter");
const unknownOnlyToggle = document.querySelector("#unknown-only");
const warningOnlyToggle = document.querySelector("#warning-only");

let currentResults = [];

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatValue(value) {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

function formatCaseType(caseType) {
  const caseMap = {
    case1: "Case 1: header only",
    case2s: "Case 2 short: header + Le",
    case3s: "Case 3 short: header + Lc + data",
    case4s: "Case 4 short: header + Lc + data + Le",
    case2e: "Case 2 extended: header + extended Le",
    case3e: "Case 3 extended: header + extended Lc + data",
    case4e: "Case 4 extended: header + extended Lc + data + Le",
  };
  return caseMap[caseType] || caseType || "n/a";
}

function renderCommands() {
  const commands = listSupportedCommands();
  const categories = new Set();
  const layers = new Set();

  supportedCommandsList.innerHTML = commands
    .map((command) => {
      categories.add(command.category);
      layers.add(command.layer);
      return `
        <li>
          <strong>${escapeHtml(command.name)}</strong>
          <span>${escapeHtml(command.category)}</span>
          <small>${escapeHtml(command.layer)}</small>
        </li>
      `;
    })
    .join("");

  categoryFilter.innerHTML = ['<option value="">All categories</option>']
    .concat([...categories].sort().map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`))
    .join("");
  layerFilter.innerHTML = ['<option value="">All layers</option>']
    .concat([...layers].sort().map((layer) => `<option value="${escapeHtml(layer)}">${escapeHtml(layer)}</option>`))
    .join("");
}

function resultSearchText(result) {
  return [
    result.commandName,
    result.category,
    result.layer,
    result.rawApdu,
    result.shortMeaning,
    result.possibleSpecArea,
    ...safeArray(result.warnings),
    ...Object.entries(result.decodedFields).flatMap(([key, value]) => [key, value]),
  ]
    .join(" ")
    .toLowerCase();
}

function filterResults(results) {
  const query = searchInput.value.trim().toLowerCase();
  const category = categoryFilter.value;
  const layer = layerFilter.value;
  const unknownOnly = unknownOnlyToggle.checked;
  const warningOnly = warningOnlyToggle.checked;

  return results.filter((result) => {
    if (category && result.category !== category) {
      return false;
    }
    if (layer && result.layer !== layer) {
      return false;
    }
    if (unknownOnly && result.commandName !== "Unknown") {
      return false;
    }
    if (warningOnly && result.warnings.length === 0) {
      return false;
    }
    if (query && !resultSearchText(result).includes(query)) {
      return false;
    }
    return true;
  });
}

function renderSummary(results, visibleResults) {
  const warningCount = results.filter((result) => result.warnings.length > 0).length;
  const unknownCount = results.filter((result) => result.commandName === "Unknown").length;
  const gpCount = results.filter((result) => result.layer.includes("GlobalPlatform")).length;
  summary.innerHTML = `
    <div class="metric"><strong>${results.length}</strong><span>Parsed</span></div>
    <div class="metric"><strong>${visibleResults.length}</strong><span>Visible</span></div>
    <div class="metric"><strong>${warningCount}</strong><span>Warnings</span></div>
    <div class="metric"><strong>${unknownCount}</strong><span>Unknown</span></div>
    <div class="metric"><strong>${gpCount}</strong><span>GP hits</span></div>
  `;
}

function renderWarningBadges(result) {
  const warningDetails = safeArray(result.warningDetails);
  if (!warningDetails.length) {
    return '<span class="badge ok">clean</span>';
  }
  return warningDetails
    .map((entry) => `<span class="badge ${entry.severity}">${escapeHtml(entry.severity)}</span>`)
    .join("");
}

function renderSections(result) {
  return safeArray(result.sections)
    .map(
      (currentSection) => `
        <section class="detail-section">
          <h4>${escapeHtml(currentSection.title)}</h4>
          <div class="detail-grid">
            ${currentSection.fields
              .map(
                (currentField) => `
                  <div class="field-card ${escapeHtml(currentField.certainty || "confirmed")}">
                    <span>${escapeHtml(currentField.label)}</span>
                    <strong>${escapeHtml(formatValue(currentField.value))}</strong>
                    ${currentField.note ? `<small>${escapeHtml(currentField.note)}</small>` : ""}
                  </div>
                `,
              )
              .join("")}
          </div>
        </section>
      `,
    )
    .join("");
}

function renderResults(results) {
  if (!results.length) {
    resultsHost.innerHTML = `
      <div class="empty-state">
        <h3>No APDUs match the current filters.</h3>
        <p>Adjust the filters or search query to widen the result set.</p>
      </div>
    `;
    return;
  }

  resultsHost.innerHTML = results
    .map(
      (result) => `
        <details class="result-card ${result.warnings.length ? "has-warning" : ""}" ${result.commandName !== "Unknown" ? "open" : ""}>
          <summary>
            <div class="result-summary">
              <div class="summary-main">
                <div class="line-badge">#${result.lineNumber}</div>
                <div>
                  <h3>${escapeHtml(result.commandName)}</h3>
                  <p>${escapeHtml(result.shortMeaning)}</p>
                </div>
              </div>
              <div class="summary-meta">
                <span>${escapeHtml(result.kind || "command-apdu")}</span>
                <span>${escapeHtml(formatCaseType(result.caseType))}</span>
                <span>${escapeHtml(result.category)}</span>
                <span>${escapeHtml(result.layer)}</span>
                <span>${escapeHtml(result.confidence)}</span>
                ${result.decodedFields.statusWord ? `<span>${escapeHtml(result.decodedFields.statusWord)}</span>` : ""}
                ${renderWarningBadges(result)}
              </div>
            </div>
            <div class="raw-row">
              <code>${escapeHtml(result.rawApdu)}</code>
            </div>
          </summary>
          <div class="result-detail">
            <div class="meta-strip">
              <div><span>Spec area</span><strong>${escapeHtml(result.possibleSpecArea)}</strong></div>
              <div><span>Logical channel</span><strong>${escapeHtml(formatValue(result.decodedFields.logicalChannel))}</strong></div>
              <div><span>Secure messaging</span><strong>${escapeHtml(formatValue(result.decodedFields.secureMessaging))}</strong></div>
              <div><span>${result.kind === "response-apdu" ? "Status word" : "Le"}</span><strong>${escapeHtml(formatValue(result.kind === "response-apdu" ? result.decodedFields.statusWord : result.le))}</strong></div>
            </div>
            ${renderSections(result)}
            ${
              safeArray(result.alternatives).length
                ? `
                  <section class="detail-section">
                    <h4>Alternative interpretations</h4>
                    <div class="detail-grid">
                      ${safeArray(result.alternatives)
                        .map(
                          (entry) => `
                            <div class="field-card possible">
                              <span>${escapeHtml(entry.layer)}</span>
                              <strong>${escapeHtml(entry.name)}</strong>
                              <small>score ${escapeHtml(entry.score)} / ${escapeHtml(entry.confidence)}</small>
                            </div>
                          `,
                        )
                        .join("")}
                    </div>
                  </section>
                `
                : ""
            }
            ${
              safeArray(result.warningDetails).length
                ? `
                  <section class="detail-section">
                    <h4>Warnings</h4>
                    <ul class="warning-list">
                      ${safeArray(result.warningDetails)
                        .map(
                          (entry) => `
                            <li class="${escapeHtml(entry.severity)}">
                              <strong>${escapeHtml(entry.severity)}</strong>
                              <span>${escapeHtml(entry.message)}</span>
                            </li>
                          `,
                        )
                        .join("")}
                    </ul>
                  </section>
                `
                : ""
            }
          </div>
        </details>
      `,
    )
    .join("");
}

function renderError(error) {
  summary.innerHTML = `
    <div class="metric">
      <strong>Error</strong>
      <span>Analysis failed</span>
    </div>
  `;
  resultsHost.innerHTML = `
    <div class="empty-state">
      <h3>Analyze failed</h3>
      <p>${escapeHtml(error?.message || String(error))}</p>
      <p>Try reloading the page once. If it still fails, the UI will now show the actual error instead of silently doing nothing.</p>
    </div>
  `;
}

function analyze() {
  try {
    currentResults = parseApduText(input.value);
    const visibleResults = filterResults(currentResults);
    renderSummary(currentResults, visibleResults);
    renderResults(visibleResults);
  } catch (error) {
    console.error("Analyze failed:", error);
    renderError(error);
  }
}

for (const element of [searchInput, categoryFilter, layerFilter, unknownOnlyToggle, warningOnlyToggle]) {
  element.addEventListener("input", analyze);
  element.addEventListener("change", analyze);
}

document.querySelector("#analyze-button").addEventListener("click", analyze);
document.querySelector("#sample-button").addEventListener("click", () => {
  input.value = sampleInput;
  analyze();
});
document.querySelector("#clear-button").addEventListener("click", () => {
  input.value = "";
  analyze();
});

input.value = sampleInput;
renderCommands();
analyze();
