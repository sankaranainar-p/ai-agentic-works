"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getConfig() {
    const cfg = vscode.workspace.getConfiguration("cac");
    return {
        engineUrl: cfg.get("engineUrl", "http://localhost:8001").replace(/\/$/, ""),
        regulation: cfg.get("regulation", "GDPR"),
        debounceMs: cfg.get("debounceMs", 600),
        enabled: cfg.get("enabled", true),
    };
}
function severityToDiagnostic(severity) {
    switch (severity) {
        case "high":
            return vscode.DiagnosticSeverity.Error;
        case "medium":
            return vscode.DiagnosticSeverity.Warning;
        case "low":
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}
/** Convert a 1-indexed line number from the engine to a 0-indexed VS Code Range. */
function findingToRange(finding, document) {
    const lastLine = document.lineCount - 1;
    // Engine returns 1-indexed lines; VS Code uses 0-indexed.
    const startLine = finding.line_start != null
        ? Math.min(finding.line_start - 1, lastLine)
        : 0;
    const endLine = finding.line_end != null
        ? Math.min(finding.line_end - 1, lastLine)
        : startLine;
    const startChar = 0;
    const endChar = document.lineAt(Math.min(endLine, lastLine)).text.length;
    return new vscode.Range(startLine, startChar, endLine, endChar);
}
function buildDiagnostic(finding, document) {
    const range = findingToRange(finding, document);
    const message = `[${finding.rule_id}] ${finding.title}: ${finding.violation} — ${finding.remediation}`;
    const diag = new vscode.Diagnostic(range, message, severityToDiagnostic(finding.severity));
    diag.source = "AI Compliance as Code";
    diag.code = finding.rule_id;
    // Attach related information when we have references
    if (finding.references.length > 0) {
        diag.relatedInformation = finding.references.slice(0, 3).map((ref) => {
            // relatedInformation requires a Location; use the finding range as a stub
            // since VS Code doesn't support bare URL links in relatedInformation.
            return new vscode.DiagnosticRelatedInformation(new vscode.Location(document.uri, range), ref);
        });
    }
    return diag;
}
// ---------------------------------------------------------------------------
// Core: call engine and populate diagnostics
// ---------------------------------------------------------------------------
async function analyzeDocument(document, diagnostics, statusBar) {
    const { engineUrl, regulation, enabled } = getConfig();
    if (!enabled) {
        diagnostics.delete(document.uri);
        return;
    }
    // Only analyse supported languages (mirrors activationEvents)
    const supported = ["python", "java", "javascript", "typescript"];
    if (!supported.includes(document.languageId)) {
        return;
    }
    statusBar.text = "$(sync~spin) CaC: analysing…";
    statusBar.show();
    try {
        const response = await fetch(`${engineUrl}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: document.getText(),
                file_path: document.fileName,
                regulation,
            }),
        });
        if (!response.ok) {
            const detail = await response.text();
            throw new Error(`Engine returned ${response.status}: ${detail}`);
        }
        const data = (await response.json());
        const diags = data.findings.map((f) => buildDiagnostic(f, document));
        diagnostics.set(document.uri, diags);
        const label = data.llm_unavailable
            ? `$(warning) CaC: ${diags.length} (static only)`
            : `$(shield) CaC: ${diags.length} finding${diags.length !== 1 ? "s" : ""}`;
        statusBar.text = label;
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        statusBar.text = `$(error) CaC: engine error`;
        // Surface transient errors as a single warning diagnostic at line 0
        diagnostics.set(document.uri, [
            new vscode.Diagnostic(new vscode.Range(0, 0, 0, 0), `AI Compliance engine error: ${msg}`, vscode.DiagnosticSeverity.Warning),
        ]);
    }
}
// ---------------------------------------------------------------------------
// Extension lifecycle
// ---------------------------------------------------------------------------
function activate(context) {
    const diagnostics = vscode.languages.createDiagnosticCollection("cac");
    context.subscriptions.push(diagnostics);
    // Status bar item — bottom-right corner
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.tooltip = "AI Compliance as Code — click to re-analyse";
    statusBar.command = "cac.analyze";
    context.subscriptions.push(statusBar);
    // Debounce timer handle per-document (keyed by document URI string)
    const debounceTimers = new Map();
    // Helper: schedule a debounced analysis for a document
    function scheduleAnalysis(document) {
        const { debounceMs } = getConfig();
        const key = document.uri.toString();
        const existing = debounceTimers.get(key);
        if (existing !== undefined) {
            clearTimeout(existing);
        }
        const timer = setTimeout(() => {
            debounceTimers.delete(key);
            analyzeDocument(document, diagnostics, statusBar);
        }, debounceMs);
        debounceTimers.set(key, timer);
    }
    // 1. On-change: debounce analysis after each keystroke
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        if (event.document.uri.scheme !== "file") {
            return;
        }
        scheduleAnalysis(event.document);
    }));
    // 2. On-open: analyse immediately when a file is opened
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((document) => {
        if (document.uri.scheme === "file") {
            scheduleAnalysis(document);
        }
    }));
    // 3. On-save: clear debounce and analyse immediately
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((document) => {
        if (document.uri.scheme !== "file") {
            return;
        }
        const key = document.uri.toString();
        const existing = debounceTimers.get(key);
        if (existing !== undefined) {
            clearTimeout(existing);
            debounceTimers.delete(key);
        }
        analyzeDocument(document, diagnostics, statusBar);
    }));
    // 4. On-close: remove stale diagnostics and cancel pending timer
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((document) => {
        const key = document.uri.toString();
        const existing = debounceTimers.get(key);
        if (existing !== undefined) {
            clearTimeout(existing);
            debounceTimers.delete(key);
        }
        diagnostics.delete(document.uri);
    }));
    // 5. Manual command: cac.analyze — run immediately on the active editor
    context.subscriptions.push(vscode.commands.registerCommand("cac.analyze", () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage("CaC: No active editor to analyse.");
            return;
        }
        analyzeDocument(editor.document, diagnostics, statusBar);
    }));
    // Show status bar immediately; analyse any already-open editors
    statusBar.text = "$(shield) CaC: ready";
    statusBar.show();
    vscode.workspace.textDocuments.forEach((doc) => {
        if (doc.uri.scheme === "file") {
            scheduleAnalysis(doc);
        }
    });
}
function deactivate() {
    // DiagnosticCollection and StatusBarItem are disposed via context.subscriptions
}
//# sourceMappingURL=extension.js.map