import path from 'path';
import * as vscode from 'vscode';
import { VulResult } from './vul_result';

export class VulTreeItem extends vscode.TreeItem {

	public filename: string;

	code: string;
	provider: string;
	startLineNumber: number;
	endLineNumber: number;

	severity: string;
	contextValue = '';

	constructor(
		public readonly title: string,
		public readonly check: VulResult,
		public collapsibleState: vscode.TreeItemCollapsibleState,
		public itemType: VulTreeItemType,
		public command?: vscode.Command,
	) {
		super(title, collapsibleState);
		super.command = command;
		this.severity = check.severity;
		this.code = "";
		this.provider = "";
		this.startLineNumber = 0;
		this.endLineNumber = 0;
		this.filename = check.filename;
		this.code = check.id;

		switch (itemType) {
			case VulTreeItemType.misconfigFile:
			case VulTreeItemType.vulnerabilityFile:
			case VulTreeItemType.secretFile:
			case VulTreeItemType.misconfigInstance:
				this.filename = check.filename;
				this.tooltip = `${check.description}`;
				this.iconPath = vscode.ThemeIcon.File;
				this.resourceUri = vscode.Uri.parse(check.filename);
				break;
			case VulTreeItemType.secretInstance:
			case VulTreeItemType.secretCode:
				this.tooltip = check.id;
				this.iconPath = {
					light: path.join(__filename, '..', '..', 'resources', 'light', 'key.svg'),
					dark: path.join(__filename, '..', '..', 'resources', 'dark', 'key.svg')
				};
				break;
			case VulTreeItemType.misconfigCode:
			case VulTreeItemType.vulnerabilityCode:
				this.tooltip = check.title;
				this.iconPath = {
					light: path.join(__filename, '..', '..', 'resources', this.severityIcon(this.severity)),
					dark: path.join(__filename, '..', '..', 'resources', this.severityIcon(this.severity))
				};
				break;
		}
	}

	severityIcon = (severity: string): string => {
		switch (severity) {
			case "CRITICAL":
				return 'critical.svg';
			case "HIGH":
				return 'high.svg';
			case "MEDIUM":
				return 'medium.svg';
			case "LOW":
				return 'low.svg';
		}
		return 'unknown.svg';
	};
}

export enum VulTreeItemType {
	misconfigCode = 0,
	misconfigInstance = 1,
	vulnerablePackage = 2,
	vulnerabilityCode = 3,
	misconfigFile = 4,
	vulnerabilityFile = 5,
	secretFile = 6,
	secretInstance = 7,
	secretCode = 8
}
