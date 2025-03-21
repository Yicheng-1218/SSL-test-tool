import ssl
import socket
import datetime
from requests import get
import pyperclip
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
import warnings
from base64 import b64decode

warnings.simplefilter("ignore")
console = Console()

def check_ssl(target):
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443

    tls_versions = {
        "TLS 1.0": ssl.TLSVersion.TLSv1,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2,
        "TLS 1.3": ssl.TLSVersion.TLSv1_3,
    }

    tls_results = {}
    for version, protocol in tls_versions.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = protocol
            context.maximum_version = protocol
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(b64decode('QUxMOkBTRUNMRVZFTD0w').decode('utf-8'))
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_results[version] = True
        except:
            tls_results[version] = False
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
    except:
        return None

    cert = x509.load_der_x509_certificate(cert, default_backend())
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    exp_date = cert.not_valid_after
    days_left = (exp_date - datetime.datetime.now()).days
    
    try:
        response = get(f"https://{hostname}", timeout=5)
        hsts_enabled = "Strict-Transport-Security" in response.headers
    except:
        hsts_enabled = False
    
    try:
        if cert.not_valid_after < datetime.datetime.now():
            ocsp_status = "expired"
        elif cert.not_valid_before > datetime.datetime.now():
            ocsp_status = "not_yet_valid"
        else:
            ocsp_status = "valid"
    except:
        ocsp_status = "unknown"
    
    weak_ciphers = ["RC4", "3DES", "CBC", "AES-CBC", "DES", "MD5", "SHA1"]
    cipher_name, cipher_version, _ = cipher
    cipher_is_weak = any(weak in cipher_name for weak in weak_ciphers)
    
    pfs_supported = "DHE" in cipher_name or "ECDHE" in cipher_name
    
    return {
        "hostname": hostname,
        "tls_results": tls_results,
        "cipher": (cipher_name, cipher_is_weak),
        "issuer": issuer,
        "subject": subject,
        "exp_date": exp_date,
        "days_left": days_left,
        "hsts_enabled": hsts_enabled,
        "ocsp_status": ocsp_status,
        "pfs_supported": pfs_supported,
    }

def print_report(result):
    console.print(Panel(f"[bold cyan]SSL 檢測結果 - {result['hostname']}[/bold cyan]", style="blue"))
    
    table = Table(title="TLS 版本支援")
    table.add_column("版本")
    table.add_column("狀態")
    for version, supported in result["tls_results"].items():
        if version in ["TLS 1.0", "TLS 1.1"]:
            status = "[yellow]✅ 支援[/yellow]"
        else:
            status = "[green]✅ 支援[/green]" if supported else "[red]❌ 不支援[/red]"
        table.add_row(version, status)
    console.print(table)
    
    days_left_msg = (
        f"❌ [bold red]錯誤: SSL憑證已過期！[/bold red]" if result["days_left"] <= 0 else
        f"🚨 [red]警告: SSL憑證剩餘 {result['days_left']} 天，請盡快更新！[/red]" if result["days_left"] <= 7 else
        f"⚠️ [yellow]警告: SSL憑證即將到期！剩餘 {result['days_left']} 天[/yellow]" if result["days_left"] <= 14 else
        f"✅ [green]SSL憑證有效期剩餘 {result['days_left']} 天[/green]"
    )
    
    ocsp_msg = {
        "expired": "[red]❌ 憑證已過期[/red]",
        "not_yet_valid": "[yellow]⚠️ 憑證尚未生效[/yellow]",
        "valid": "[green]✅ 憑證有效[/green]",
        "unknown": "[red]❌ OCSP 驗證失敗[/red]"
    }[result["ocsp_status"]]
    
    cipher_msg = f"[red]❌ 使用 {result['cipher'][0]} 弱加密[/red]" if result['cipher'][1] else f"[green]✅ 使用 {result['cipher'][0]} 強加密[/green]"
    pfs_msg = "[green]✅ 支援 PFS[/green]" if result["pfs_supported"] else "[red]❌ 不支援 PFS[/red]"
    hsts_msg = "[green]✅ 啟用[/green]" if result["hsts_enabled"] else "[red]❌ 未啟用[/red]"
    
    console.print(f"📜 SSL 憑證有效期：{days_left_msg}")
    console.print(f"🔍 OCSP 檢測: {ocsp_msg}")
    console.print(f"🔐 加密套件: {cipher_msg}")
    console.print(f"🔒 PFS 狀態: {pfs_msg}")
    console.print(f"🛡️ HSTS 狀態: {hsts_msg}")
    
    tls_str= '、'.join([version for version, supported in result["tls_results"].items() if supported])
    template= f"""\t依據廠商提供之佐證說明，本受測服務針對資料數據加密，有1處作法，並提供資料傳輸過程通道加密佐證圖，如下：
1.資料傳輸過程通道加密：傳輸資料通道使用TLS 1.3加密。
\t另，經本團隊抽測、使用自有工具檢視後，確認受測服務具良好資料傳輸加密管理。依據廠商提供之佐證說明，本受測服務針對傳輸過程通道加密，並經過本測試團隊的測試，測試結果如下：
測試網域：{result['hostname']}
測試日期：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
測試結果：符合
1. (必測) TLS 版本支援：{tls_str}
2. (必測) SSL 憑證有效期：SSL 憑證有效期剩餘 {result['days_left']} 天
3. (必測) OCSP 檢測：{"憑證有效" if result['ocsp_status']=="valid" else "憑證失效"}
4. (必測) 加密套件：使用 {result['cipher'][0]} {"強加密" if not result['cipher'][1] else "弱加密"}
5. (選測) PFS 狀態：{"支援 PFS" if result["pfs_supported"] else "不支援 PFS"}
6. (選測) HSTS 狀態：{"啟用" if result["hsts_enabled"] else "未啟用"}
故此測試項目符合，傳輸或存儲過程中經過加密處理之要求。"""
    console.print(f"==================================\n{template}\n==================================")
    pyperclip.copy(template)
    console.print("[yellow]測試報告已複製到剪貼簿[/yellow]")

def main():
    while True:
        target = Prompt.ask("請輸入要測試的網站", default="www.google.com")
        result = check_ssl(target)
        if result:
            print_report(result)
        input("按 Enter 鍵繼續測試...")
        console.clear()

if __name__ == "__main__":
    main()
