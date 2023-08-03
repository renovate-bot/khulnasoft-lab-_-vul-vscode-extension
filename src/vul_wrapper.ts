import * as vscode from 'vscode';
import * as child from 'child_process';
import { v4 as uuid } from 'uuid';
import * as path from 'path';
import { unlinkSync, readdirSync } from 'fs';

export class VulWrapper {
    private workingPath: string[] = [];
    constructor(
        private outputChannel: vscode.OutputChannel,
        private readonly resultsStoragePath: string) {
        if (!vscode.workspace || !vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length <= 0) {
            return;
        }
        const folders = vscode.workspace.workspaceFolders;
        for (let i = 0; i < folders.length; i++) {
            if (folders[i]) {
                const workspaceFolder = folders[i];
                if (!workspaceFolder) {
                    continue;
                }
                this.workingPath.push(workspaceFolder.uri.fsPath);
            }
        }
    }

    run() {
        let outputChannel = this.outputChannel;
        this.outputChannel.appendLine("");
        this.outputChannel.appendLine("Running Vul to update results");

        if (!this.checkVulInstalled()) {
            return;
        }

        var files = readdirSync(this.resultsStoragePath).filter(fn => fn.endsWith('_results.json') || fn.endsWith('_results.json.json'));
        files.forEach(file => {
            let deletePath = path.join(this.resultsStoragePath, file);
            unlinkSync(deletePath);
        });

        const binary = this.getBinaryPath();

        this.workingPath.forEach(workingPath => {
            let command = this.buildCommand(workingPath);
            this.outputChannel.appendLine(`command: ${command}`);

            var execution = child.spawn(binary, command);

            execution.stdout.on('data', function (data) {
                outputChannel.appendLine(data.toString());
            });

            execution.stderr.on('data', function (data) {
                outputChannel.appendLine(data.toString());
            });

            execution.on('exit', function (code) {
                if (code !== 0) {
                    vscode.window.showErrorMessage("Vul failed to run");
                    return;
                };
                vscode.window.showInformationMessage('Vul ran successfully, updating results');
                outputChannel.appendLine('Reloading the Findings Explorer content');
                setTimeout(() => { vscode.commands.executeCommand("vul-vulnerability-scanner.refresh"); }, 250);
            });
        });

    }

    showCurrentVulVersion() {
        const currentVersion = this.getInstalledVulVersion();
        if (currentVersion) {
            vscode.window.showInformationMessage(`Current Vul version is ${currentVersion}`);
        }
    }

    private getBinaryPath() {
        const config = vscode.workspace.getConfiguration('vul');
        var binary = config.get('binaryPath', 'vul');
        if (binary === "") {
            binary = "vul";
        }

        return binary;
    };

    private checkVulInstalled(): boolean {
        const binaryPath = this.getBinaryPath();

        var command = [];
        command.push(binaryPath);
        command.push('--help');
        try {
            child.execSync(command.join(' '));
        }
        catch (err) {
            this.outputChannel.show();
            this.outputChannel.appendLine(`Vul not found. Check the Vul extension settings to ensure the path is correct. [${binaryPath}]`);
            return false;
        }
        return true;
    };

    private getInstalledVulVersion(): string {

        if (!this.checkVulInstalled) {
            vscode.window.showErrorMessage("Vul could not be found, check Output window");
            return "";
        }

        let binary = this.getBinaryPath();

        var command = [];
        command.push(binary);
        command.push('--version');
        const getVersion = child.execSync(command.join(' '));
        return getVersion.toString();
    };


    private buildCommand(workingPath: string): string[] {
        const config = vscode.workspace.getConfiguration('vul');
        var command = [];


        if (config.get<boolean>('debug')) {
            command.push('--debug');
        }

        let requireChecks = "config,vuln";
        if (config.get<boolean>("secretScanning")) {
            requireChecks = `${requireChecks},secret`;
        }
        command.push("fs");
        command.push(`--security-checks=${requireChecks}`);
        command.push(this.getRequiredSeverities(config));

        if (config.get<boolean>("offlineScan")) {
            command.push('--offline-scan');
        }

        if (config.get<boolean>("fixedOnly")) {
            command.push('--ignore-unfixed');
        }

        if (config.get<boolean>("server.enable")) {
            command.push('--server');
            command.push(`${config.get<string>("server.url")}`);
        }

        

        command.push('--format=json');
        const resultsPath = path.join(this.resultsStoragePath, `${uuid()}_results.json`);
        command.push(`--output=${resultsPath}`);

        command.push(workingPath);
        return command;
    }


    private getRequiredSeverities(config: vscode.WorkspaceConfiguration): string {

        let requiredSeverities: string[] = [];

        const minRequired = config.get<string>("minimumReportedSeverity");
        const severities: string[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

        for (let i = 0; i < severities.length; i++) {
            const s = severities[i];
            if (!s) {
                continue;
            }
            requiredSeverities.push(s);
            if (s === minRequired) {
                break;
            }
        }

        return `--severity=${requiredSeverities.join(",")}`;
    }
}

