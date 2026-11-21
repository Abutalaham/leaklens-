"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const http = require("http");
const url = require("url");
let diagnosticCollection;
let statusBarItem;
function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('leaklens');
    context.subscriptions.push(diagnosticCollection);
    // Status Bar Indicator
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'leaklens.scanCurrentFile';
    statusBarItem.text = '$(shield) LeakLens Guard';
    statusBarItem.tooltip = 'Click to scan active file for secrets and leaks';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    // Commands
    context.subscriptions.push(vscode.commands.registerCommand('leaklens.scanCurrentFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            scanDocument(editor.document, true);
        }
        else {
            vscode.window.showInformationMessage('LeakLens: No active file to scan.');
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('leaklens.clearDiagnostics', () => {
        diagnosticCollection.clear();
        vscode.window.showInformationMessage('LeakLens: Diagnostics cleared.');
    }));
    // Workspace-wide scan command
    context.subscriptions.push(vscode.commands.registerCommand('leaklens.scanWorkspace', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            vscode.window.showInformationMessage('LeakLens: No workspace folder open.');
            return;
        }
        const config = vscode.workspace.getConfiguration('leaklens');
        const backendUrl = config.get('backendUrl', 'http://127.0.0.1:5000');
        // Gather all scannable text files in workspace (excluding ignored dirs)
        const pattern = new vscode.RelativePattern(folders[0], '**/*.{py,js,ts,jsx,tsx,java,rb,go,php,cs,cpp,c,h,sh,bash,yml,yaml,json,env,cfg,conf,ini,toml,txt,md}');
        const files = await vscode.workspace.findFiles(pattern, '{**/node_modules/**,**/.git/**,**/.venv/**,**/venv/**,**/__pycache__/**,**/dist/**,**/build/**}');
        if (files.length === 0) {
            vscode.window.showInformationMessage('LeakLens: No scannable source files found in workspace.');
            return;
        }
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'LeakLens: Scanning Workspace',
            cancellable: true,
        }, async (progress, token) => {
            diagnosticCollection.clear();
            let scanned = 0;
            let totalFindings = 0;
            const increment = 100 / files.length;
            for (const fileUri of files) {
                if (token.isCancellationRequested) {
                    break;
                }
                progress.report({
                    increment,
                    message: `${scanned + 1}/${files.length}: ${vscode.workspace.asRelativePath(fileUri)}`,
                });
                try {
                    const doc = await vscode.workspace.openTextDocument(fileUri);
                    const content = doc.getText();
                    const filename = doc.fileName;
                    const res = await callBackendScan(backendUrl, filename, content);
                    if (res && res.diagnostics && res.diagnostics.length > 0) {
                        const diagnostics = [];
                        for (const d of res.diagnostics) {
                            if (d.status !== 'active')
                                continue;
                            const line = Math.max(0, d.line - 1);
                            const col = Math.max(0, d.col - 1);
                            const endLine = Math.max(0, d.end_line - 1);
                            const endCol = Math.max(col + 1, d.end_col - 1);
                            const range = new vscode.Range(new vscode.Position(line, col), new vscode.Position(endLine, endCol));
                            const severity = d.severity === 'error'
                                ? vscode.DiagnosticSeverity.Error
                                : d.severity === 'warning'
                                    ? vscode.DiagnosticSeverity.Warning
                                    : vscode.DiagnosticSeverity.Information;
                            const diag = new vscode.Diagnostic(range, `${d.message} [Masked: ${d.preview}]`, severity);
                            diag.source = 'LeakLens Guard';
                            diag.code = { value: d.env_var || d.type, target: vscode.Uri.parse(backendUrl) };
                            diag.suggested_fix = d.suggested_fix;
                            diag.env_var = d.env_var;
                            diagnostics.push(diag);
                        }
                        if (diagnostics.length > 0) {
                            diagnosticCollection.set(fileUri, diagnostics);
                            totalFindings += diagnostics.length;
                        }
                    }
                }
                catch (_err) {
                    // Skip files that cannot be scanned (binary, permission errors)
                }
                scanned++;
            }
            if (totalFindings === 0) {
                vscode.window.showInformationMessage(`LeakLens: Workspace scan complete — ${scanned} files scanned. No secrets found!`);
            }
            else {
                vscode.window.showWarningMessage(`LeakLens: Workspace scan complete — ${totalFindings} potential secret(s) found across ${scanned} files. Check Problems panel.`);
            }
        });
    }));
    // Auto-scan on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
        const config = vscode.workspace.getConfiguration('leaklens');
        if (config.get('scanOnSave', true)) {
            scanDocument(doc, false);
        }
    }));
    // Quick Fix Code Action Provider
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider(['javascript', 'typescript', 'python', 'java', 'json', 'yaml', 'plaintext'], new LeakLensFixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
}
function shouldIgnore(doc) {
    const fsPath = doc.uri.fsPath.replace(/\\/g, '/');
    const ignorePatterns = [
        '/node_modules/',
        '/.git/',
        '/.venv/',
        '/venv/',
        '/__pycache__/',
        '/dist/',
        '/build/',
    ];
    return ignorePatterns.some((pattern) => fsPath.includes(pattern));
}
async function scanDocument(doc, notify) {
    if (doc.isUntitled || shouldIgnore(doc)) {
        return;
    }
    const config = vscode.workspace.getConfiguration('leaklens');
    const backendUrl = config.get('backendUrl', 'http://127.0.0.1:5000');
    const content = doc.getText();
    const filename = doc.fileName;
    try {
        const res = await callBackendScan(backendUrl, filename, content);
        diagnosticCollection.delete(doc.uri);
        if (!res || !res.diagnostics) {
            return;
        }
        const diagnostics = [];
        for (const d of res.diagnostics) {
            const line = Math.max(0, d.line - 1);
            const col = Math.max(0, d.col - 1);
            const endLine = Math.max(0, d.end_line - 1);
            const endCol = Math.max(col + 1, d.end_col - 1);
            const range = new vscode.Range(new vscode.Position(line, col), new vscode.Position(endLine, endCol));
            const severity = d.severity === 'error'
                ? vscode.DiagnosticSeverity.Error
                : d.severity === 'warning'
                    ? vscode.DiagnosticSeverity.Warning
                    : vscode.DiagnosticSeverity.Information;
            const diag = new vscode.Diagnostic(range, `${d.message} [Masked: ${d.preview}]`, severity);
            diag.source = 'LeakLens Guard';
            diag.code = {
                value: d.env_var || d.type,
                target: vscode.Uri.parse('http://127.0.0.1:5000'),
            };
            // Store suggested fix in custom field
            diag.suggested_fix = d.suggested_fix;
            diag.env_var = d.env_var;
            diagnostics.push(diag);
        }
        diagnosticCollection.set(doc.uri, diagnostics);
        if (notify) {
            if (diagnostics.length === 0) {
                vscode.window.showInformationMessage('LeakLens: No secrets or sensitive data detected in this file.');
            }
            else {
                vscode.window.showWarningMessage(`LeakLens: Detected ${diagnostics.length} potential secret(s) in ${vscode.workspace.asRelativePath(doc.uri)}.`);
            }
        }
    }
    catch (err) {
        if (notify) {
            vscode.window.showErrorMessage(`LeakLens: Unable to connect to local scanner at ${backendUrl}. Ensure 'python app.py' is running.`);
        }
    }
}
function callBackendScan(backendUrl, filename, content) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({ filename, content });
        const parsed = url.parse(`${backendUrl.replace(/\/+$/, '')}/api/ide/scan`);
        const req = http.request({
            hostname: parsed.hostname || '127.0.0.1',
            port: parsed.port || 5000,
            path: parsed.path || '/api/ide/scan',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData),
            },
            timeout: 5000,
        }, (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                }
                catch (e) {
                    reject(e);
                }
            });
        });
        req.on('error', (err) => reject(err));
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });
        req.write(postData);
        req.end();
    });
}
class LeakLensFixProvider {
    provideCodeActions(document, range, context) {
        const actions = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'LeakLens Guard' && diagnostic.suggested_fix) {
                const fixCode = diagnostic.suggested_fix;
                const envVar = diagnostic.env_var;
                const action = new vscode.CodeAction(`LeakLens: Replace secret literal with ${fixCode}`, vscode.CodeActionKind.QuickFix);
                action.diagnostics = [diagnostic];
                action.isPreferred = true;
                action.edit = new vscode.WorkspaceEdit();
                action.edit.replace(document.uri, diagnostic.range, fixCode);
                actions.push(action);
            }
        }
        return actions;
    }
}
function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
}
//# sourceMappingURL=extension.js.map