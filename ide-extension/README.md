# LeakLens IDE Guard — VS Code Extension

Real-time, local privacy and secret detection for Visual Studio Code. Protect your codebase from accidental credential leaks before they reach Git or team chats.

## Features
- **Automatic Scan on Save:** Scans the active file immediately when saved.
- **In-Editor Diagnostics:** Highlights suspected API keys, private tokens, passwords, and PII directly in the editor line and column.
- **Privacy-Preserving:** Never logs or uploads secret values. Runs 100% locally against your local LeakLens backend (`http://127.0.0.1:5000/api/ide/scan`).
- **One-Click QuickFix:** Suggests safe environment variable replacements (`os.environ.get('VAR')` for Python, `process.env.VAR` for JS/TS).
- **Safe Exclusions:** Automatically skips `node_modules`, `.git`, virtual environments (`.venv`), and build directories.

## Installation & Setup

1. Start your local LeakLens backend:
   ```bash
   python app.py
   ```
2. In VS Code, open the `ide-extension/` directory.
3. Install dependencies and compile:
   ```bash
   npm install
   npm run compile
   ```
4. Press `F5` in VS Code to launch the extension in a new Extension Development Host window.
5. Alternatively, package with `vsce package` and install the generated `.vsix`.

## Extension Settings
- `leaklens.backendUrl`: Local LeakLens service URL (default: `http://127.0.0.1:5000`).
- `leaklens.scanOnSave`: Enable/disable automatic scanning upon file save (default: `true`).
- `leaklens.ignoreFolders`: Array of folder glob patterns to exclude from scanning.
