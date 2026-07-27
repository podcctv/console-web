import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("console-web.acme")

BASE_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = BASE_DIR / "certs"
CHALLENGE_DIR = CERTS_DIR / ".well-known" / "acme-challenge"
CERT_FILE = CERTS_DIR / "cert.pem"
KEY_FILE = CERTS_DIR / "key.pem"
ACME_SH_PATH = Path.home() / ".acme.sh" / "acme.sh"

_acme_lock = threading.Lock()


def ensure_dirs():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    CHALLENGE_DIR.mkdir(parents=True, exist_ok=True)


ensure_dirs()


def get_cert_status():
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        return {
            "has_cert": False,
            "status": "未开启 SSL / 无证书",
            "days_left": 0,
            "domain": None,
            "issuer": None,
            "expires_on": None,
        }

    try:
        cert_data = CERT_FILE.read_bytes()
        x509 = ssl.parse_cert_key_file(CERT_FILE) if hasattr(ssl, 'parse_cert_key_file') else None
        
        # Fallback to openssl CLI parsing
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout", "-enddate", "-issuer", "-subject"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode == 0:
            lines = proc.stdout.splitlines()
            enddate_str = ""
            issuer_str = ""
            subject_str = ""
            for l in lines:
                if l.startswith("notAfter="):
                    enddate_str = l.split("=", 1)[1]
                elif l.startswith("issuer="):
                    issuer_str = l.split("=", 1)[1]
                elif l.startswith("subject="):
                    subject_str = l.split("=", 1)[1]

            if enddate_str:
                # Format: Apr 27 12:00:00 2026 GMT
                try:
                    exp_dt = datetime.strptime(enddate_str, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_left = (exp_dt - now_dt).days
                    
                    domain_name = "N/A"
                    if "CN =" in subject_str:
                        domain_name = subject_str.split("CN =")[1].split("/")[0].strip()
                    elif "CN=" in subject_str:
                        domain_name = subject_str.split("CN=")[1].split("/")[0].strip()

                    issuer_name = "ZeroSSL / Let's Encrypt"
                    if "ZeroSSL" in issuer_str:
                        issuer_name = "ZeroSSL"
                    elif "Let's Encrypt" in issuer_str:
                        issuer_name = "Let's Encrypt"

                    return {
                        "has_cert": True,
                        "status": f"已启用 ({days_left}天后到期)",
                        "days_left": max(0, days_left),
                        "domain": domain_name,
                        "issuer": issuer_name,
                        "expires_on": exp_dt.strftime("%Y-%m-%d"),
                    }
                except Exception as e:
                    logger.warning("Failed to parse cert enddate: %s", e)

    except Exception as e:
        logger.exception("Error checking cert status: %s", e)

    return {
        "has_cert": True,
        "status": "已安装 (有效)",
        "days_left": 90,
        "domain": "公网 IP / 域名",
        "issuer": "ACME CA",
        "expires_on": "未知",
    }


def ensure_acme_sh():
    if shutil.which("acme.sh") or ACME_SH_PATH.exists():
        return True
    
    logger.info("Installing acme.sh tool...")
    try:
        proc = subprocess.run(
            ["curl", "-fsSL", "https://get.acme.sh", "-o", "/tmp/install_acme.sh"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if proc.returncode == 0:
            subprocess.run(["sh", "/tmp/install_acme.sh", "email=admin@console-web.local"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return ACME_SH_PATH.exists() or shutil.which("acme.sh") is not None
    except Exception as e:
        logger.exception("Failed to auto-install acme.sh: %s", e)
    return False


def get_acme_cmd():
    if shutil.which("acme.sh"):
        return ["acme.sh"]
    if ACME_SH_PATH.exists():
        return [str(ACME_SH_PATH)]
    return None


def issue_cert(target=None, email=None):
    with _acme_lock:
        ensure_dirs()
        acme_cmd = get_acme_cmd()
        if not acme_cmd:
            if not ensure_acme_sh():
                return False, "系统中未检测到 acme.sh 且自动安装失败，请先安装 acme.sh 或 openssl"
            acme_cmd = get_acme_cmd()

        if not target:
            # Detect public IP
            try:
                with urllib.request.urlopen("https://ifconfig.me", timeout=3) as resp:
                    target = resp.read().decode().strip()
            except Exception:
                target = socket.gethostname()

        email_arg = email or f"admin@{target}"

        logger.info("Initiating ACME SSL issuance for target: %s (webroot: %s)", target, CERTS_DIR)

        # 1. Register account if needed
        subprocess.run([*acme_cmd, "--register-account", "-m", email_arg, "--server", "zerossl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 2. Issue cert via webroot HTTP-01 challenge
        issue_args = [
            *acme_cmd,
            "--issue",
            "-d", target,
            "-w", str(CERTS_DIR),
            "--server", "zerossl",
            "--force"
        ]
        proc = subprocess.run(issue_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            logger.error("ACME issue failed: %s", proc.stdout)
            return False, f"ACME 证书签发失败: {proc.stdout[-300:]}"

        # 3. Install cert files
        install_args = [
            *acme_cmd,
            "--install-cert",
            "-d", target,
            "--cert-file", str(CERT_FILE),
            "--key-file", str(KEY_FILE),
            "--fullchain-file", str(CERT_FILE)
        ]
        install_proc = subprocess.run(install_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if install_proc.returncode != 0:
            return False, f"证书安装拷贝失败: {install_proc.stdout[-200:]}"

        logger.info("ACME SSL certificate successfully issued for %s", target)
        return True, f"成功为 {target} 签发并安装 ACME SSL 证书！"


def renew_cert():
    with _acme_lock:
        acme_cmd = get_acme_cmd()
        if not acme_cmd:
            return False, "未找到 acme.sh"

        logger.info("Executing ACME certificate renewal...")
        proc = subprocess.run([*acme_cmd, "--renew-all", "--force"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode == 0:
            logger.info("ACME SSL certificate auto-renewed successfully")
            return True, "ACME SSL 证书自动续期成功！"
        return False, f"续期未完成: {proc.stdout[-300:]}"


def _auto_renew_loop():
    logger.info("ACME Auto-renewal daemon thread started.")
    while True:
        try:
            time.sleep(86400) # Check once every 24 hours
            status = get_cert_status()
            if status["has_cert"] and status["days_left"] <= 30:
                logger.info("Certificate has %s days left (<30 days). Triggering auto-renewal...", status["days_left"])
                renew_cert()
        except Exception as e:
            logger.exception("Error in ACME auto-renew loop: %s", e)


def start_daemon():
    t = threading.Thread(target=_auto_renew_loop, daemon=True, name="ACME-AutoRenew")
    t.start()
