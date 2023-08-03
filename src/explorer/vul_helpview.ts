import { CancellationToken, Webview, WebviewView, WebviewViewProvider, WebviewViewResolveContext } from "vscode";
import { Misconfiguration, VulResult, Vulnerability, Secret } from "./vul_result";
import { VulTreeItem, VulTreeItemType } from "./vul_treeitem";


export class VulHelpProvider implements WebviewViewProvider {
    private view: Webview | undefined;

    resolveWebviewView(webviewView: WebviewView, _context: WebviewViewResolveContext<unknown>, _token: CancellationToken): void | Thenable<void> {
        this.view = webviewView.webview;
        this.update(null);
    }

    update(item: VulTreeItem | null) {
        if (this.view === undefined) {
            return;
        }
        if (item === null) {
            return;
        }
        const codeData = item.check;
        if (codeData === undefined) {
            this.view.html = `
<h2>No check data available</h2>
`;
            return;
        }

        var html: string = "";
        switch (item.itemType) {
            case VulTreeItemType.misconfigCode:
            case VulTreeItemType.misconfigInstance:
                html = getMisconfigurationHtml(item.check);
                break;
            case VulTreeItemType.vulnerabilityCode:
                html = getVulnerabilityHtml(item.check);
                break;
            case VulTreeItemType.secretInstance:
                html = getSecretHtml(item.check);
                break;
            default:
                return "";
        }

        if (codeData.references) {

            html += "<ul>";
            for (let i = 0; i < codeData.references.length; i++) {
                const reference = codeData.references[i];
                html += `<li><a href="${reference}">${reference}</a></li>
            `;
            }
            html += "</ul>";
        }

        this.view.html = html;
        return;
    }

}

function getVulnerabilityHtml(result: VulResult): string {
    const vulnerability = result.extraData as Vulnerability;
    if (vulnerability === undefined) {
        return "";
    }
    return `
    <h2>${result.id}</h2>
    
    <h3>${result.title}</h3>
    ${result.description}

    <h3>Severity</h3>
    ${result.severity}

    <h3>Package Name</h3>
    ${vulnerability.pkgName}

    <h3>Installed Version</h3>
    ${vulnerability.installedVersion}

    <h3>Fixed Version</h3>
    ${vulnerability.fixedVersion}

    <h3>Filename</h3>
    ${result.filename}

    <h3>More Information</h3>
    `;
}


function getMisconfigurationHtml(result: VulResult): string {
    const misconfig = result.extraData as Misconfiguration;
    if (misconfig === undefined) {
        return "";
    }
    return `
    <h2>${result.id}</h2>
    
    <h3>${result.title}</h3>
    ${result.description}


    <h3>Severity</h3>
    ${result.severity}

    <h3>Resolution</h3>
    ${misconfig.resolution}

    <h3>Filename</h3>
    ${result.filename}

    <h3>More Information</h3>
    `;
}

function getSecretHtml(result: VulResult): string {
    const secret = result.extraData as Secret;
    if (secret === undefined) {
        return "";
    }
    return `
    <h2>${result.title}</h2>

    <h3>Severity</h3>
    ${result.severity}

    <h3>Match</h3>
    ${secret.match}

    <h3>Filename</h3>
    ${result.filename}

    `;
}
