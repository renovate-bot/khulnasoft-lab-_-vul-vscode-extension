import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { Misconfiguration, processResult, Secret, VulResult, Vulnerability } from './vul_result';
import { VulTreeItem, VulTreeItemType } from './vul_treeitem';
import { sortBySeverity } from './utils';

export class VulTreeViewProvider implements vscode.TreeDataProvider<VulTreeItem> {

	private _onDidChangeTreeData: vscode.EventEmitter<VulTreeItem | undefined | void> = new vscode.EventEmitter<VulTreeItem | undefined | void>();
	readonly onDidChangeTreeData: vscode.Event<VulTreeItem | undefined | void> = this._onDidChangeTreeData.event;
	public resultData: VulResult[] = [];
	private taintResults: boolean = true;
	private storagePath: string = "";
	public readonly resultsStoragePath: string = "";

	constructor(context: vscode.ExtensionContext) {
		if (context.storageUri) {
			this.storagePath = context.storageUri.fsPath;
			console.log(`storage path is ${this.storagePath}`);
			if (!fs.existsSync(this.storagePath)) {
				fs.mkdirSync(this.storagePath);
			}
			this.resultsStoragePath = path.join(this.storagePath, '/.vul/');
			if (!fs.existsSync(this.resultsStoragePath)) {
				fs.mkdirSync(this.resultsStoragePath);
			}
		}
	}

	refresh(): void {
		this.taintResults = true;
		this.loadResultData();
	}

	// when there is vul output file, load the results
	async loadResultData() {
		var _self = this;
		_self.resultData = [];
		if (this.resultsStoragePath !== "" && vscode.workspace && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0]) {
			var files = fs.readdirSync(this.resultsStoragePath).filter(fn => fn.endsWith('_results.json') || fn.endsWith('_results.json.json'));
			Promise.resolve(files.forEach(file => {
				const resultFile = path.join(this.resultsStoragePath, file);
				if (fs.existsSync(resultFile)) {
					let content = fs.readFileSync(resultFile, 'utf8');
					try {
						const data = JSON.parse(content);
						if (data === null || data.results === null) {
							return;
						}
						let results = data.Results;
						for (let i = 0; i < results.length; i++) {
							const element = results[i];
							const vulResults = processResult(element);
							_self.resultData.push(...vulResults);
						}
					}
					catch (error) {
						console.debug(`Error loading results file ${file}: ${error}`);
					}
				}
			})).then(() => {
				_self.taintResults = !_self.taintResults;
				_self._onDidChangeTreeData.fire();
			});
		} else {
			vscode.window.showInformationMessage("No workspace detected to load Vul results from");
		}
		this.taintResults = false;
	}

	getTreeItem(element: VulTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: VulTreeItem): Thenable<VulTreeItem[]> {
		// if this is refresh then get the top level codes
		let items: VulTreeItem[] = [];
		if (!element) {
			items = this.getTopLevelNodes();
		} else {
			items = this.getChildNodes(element);
		}
		return Promise.resolve(items);
	}


	private getVulnerabilityChildren(element: VulTreeItem): VulTreeItem[] {

		let results: VulTreeItem[] = [];
		const filtered = this.resultData.filter(c => c.extraData instanceof Vulnerability
			&& c.extraData.pkgName === element.title);

		for (let index = 0; index < filtered.length; index++) {
			const result = filtered[index];

			if (result === undefined) {
				continue;
			}

			const title = `${result.id}`;
			const collapsedState = vscode.TreeItemCollapsibleState.None;

			var item = new VulTreeItem(title, result, collapsedState, VulTreeItemType.vulnerabilityCode, this.createFileOpenCommand(result));
			results.push(item);
		}

		return results;
	}

	getSecretInstances(element: VulTreeItem): VulTreeItem[] {
		let results: VulTreeItem[] = [];
		const filtered = this.resultData.filter(c => c.id === element.code && c.filename === element.filename);

		for (let index = 0; index < filtered.length; index++) {
			const result = filtered[index];

			if (result === undefined) {
				continue;
			}

			const title = result.id;
			const collapsedState = vscode.TreeItemCollapsibleState.None;

			var item = new VulTreeItem(title, result, collapsedState, VulTreeItemType.secretInstance, this.createFileOpenCommand(result));
			results.push(item);
		}

		return results;
	}

	getMisconfigurationInstances(element: VulTreeItem): VulTreeItem[] {
		let results: VulTreeItem[] = [];
		const filtered = this.resultData.filter(c => c.id === element.code && c.filename === element.filename);

		for (let index = 0; index < filtered.length; index++) {
			const result = filtered[index];

			if (result === undefined) {
				continue;
			}

			const title = `${result.filename}:[${result.startLine}-${result.endLine}]`;
			const collapsedState = vscode.TreeItemCollapsibleState.None;

			var item = new VulTreeItem(title, result, collapsedState, VulTreeItemType.misconfigInstance, this.createFileOpenCommand(result));
			results.push(item);
		}

		return results;
	}

	private getChildNodes(element: VulTreeItem): VulTreeItem[] {
		let vulResults: VulTreeItem[] = [];
		var filtered: VulResult[];
		switch (element.itemType) {
			case VulTreeItemType.vulnerablePackage:
				return this.getVulnerabilityChildren(element);
			case VulTreeItemType.misconfigCode:
				return this.getMisconfigurationInstances(element);
			case VulTreeItemType.secretFile:
				return this.getSecretInstances(element);
		}


		switch (element.itemType) {
			case VulTreeItemType.misconfigFile:
				filtered = this.resultData.filter(c => c.filename === element.filename);
				filtered.sort(sortBySeverity);
				break;
			default:
				filtered = this.resultData.filter(c => c.filename === element.filename);
		}




		var resolvedNodes: string[] = [];
		for (let index = 0; index < filtered.length; index++) {
			const result = filtered[index];

			if (result === undefined) {
				continue;
			}

			switch (element.itemType) {
				case VulTreeItemType.misconfigFile:
					if (resolvedNodes.includes(result.id)) {
						continue;
					}

					resolvedNodes.push(result.id);
					if (result.extraData instanceof Secret) {
						vulResults.push(new VulTreeItem(result.id, result, vscode.TreeItemCollapsibleState.None, VulTreeItemType.secretInstance,  this.createFileOpenCommand(result)));
					} else {
						vulResults.push(new VulTreeItem(result.id, result, vscode.TreeItemCollapsibleState.Collapsed, VulTreeItemType.misconfigCode));
					}
					
					break;
				case VulTreeItemType.vulnerabilityFile:
					const extraData = result.extraData;

					if (extraData instanceof Vulnerability) {
						if (resolvedNodes.includes(extraData.pkgName)) {
							continue;
						}
						resolvedNodes.push(extraData.pkgName);
						vulResults.push(new VulTreeItem(extraData.pkgName, result, vscode.TreeItemCollapsibleState.Collapsed, VulTreeItemType.vulnerablePackage));
					}
					break;
			}
		
		}
		return vulResults;
	}

	private getTopLevelNodes(): VulTreeItem[] {
		var results: VulTreeItem[] = [];
		var resolvedNodes: string[] = [];
		for (let index = 0; index < this.resultData.length; index++) {
			const result = this.resultData[index];
			if (result === undefined) {
				continue;
			}

			if (resolvedNodes.includes(result.filename)) {
				continue;
			}

			resolvedNodes.push(result.filename);

			const itemType = result.extraData instanceof Vulnerability ? VulTreeItemType.vulnerabilityFile :
				result.extraData instanceof Misconfiguration ? VulTreeItemType.misconfigFile : VulTreeItemType.secretFile;
			results.push(new VulTreeItem(result.filename, result, vscode.TreeItemCollapsibleState.Collapsed, itemType));
		}
		return results;
	}


	private createFileOpenCommand(result: VulResult): vscode.Command | undefined {
		const issueRange = new vscode.Range(new vscode.Position(result.startLine - 1, 0), new vscode.Position(result.endLine, 0));
		if (vscode.workspace.workspaceFolders === undefined || vscode.workspace.workspaceFolders.length < 1) {
			return;
		}
		const wsFolder = vscode.workspace.workspaceFolders[0];
		if (!wsFolder) {
			return;
		}

		let fileUri = path.join(wsFolder.uri.fsPath, result.filename);

		if (!fs.existsSync(fileUri)) {
			return;
		}


		return {
			command: "vscode.open",
			title: "",
			arguments: [
				vscode.Uri.file(fileUri),
				{
					selection: (result.startLine === result.endLine && result.startLine === 0) ? null : issueRange,
				}
			]
		};
	}
}
