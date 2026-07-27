"""
ACME SSL Certificate Auto-Manager (Official Web/IP Certificates Only)
===================================================================
1. Strictly issues ONLY official ACME certificates (ZeroSSL / Let's Encrypt)
2. NEVER generates or accepts self-signed certificates
3. Automatically detects, deletes legacy self-signed certs and re-triggers ACME issuance
4. Daemon thread checks cert validity and auto-renews before expiration
"""

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
META_FILE = CERTS_DIR / "acme_meta.json"
ACME_SH_PATH = Path.home() / ".acme.sh" / "acme.sh"

_acme_lock = threading.Lock()


def ensure_dirs():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    CHALLENGE_DIR.mkdir(parents=True, exist_ok=True)


ensure_dirs()


def _save_meta(target: str, email: str):
    try:
        META_FILE.write_text(json.dumps({"target": target, "email": email, "issued_at": time.time()}))
    except Exception:
        pass


def _load_meta() -> dict:
    try:
        if META_FILE.exists():
            return json.loads(META_FILE.read_text())
    except Exception:
        pass
    return {}


def remove_cert_files():
    """Delete existing certificate files (e.g. self-signed certs)."""
    try:
        if CERT_FILE.exists():
            CERT_FILE.unlink()
        if KEY_FILE.exists():
            KEY_FILE.unlink()
        if META_FILE.exists():
            META_FILE.unlink()
        logger.info("Deleted certificate files (%s, %s)", CERT_FILE, KEY_FILE)
    except Exception as e:
        logger.warning("Failed to delete certificate files: %s", e)


def is_self_signed_cert() -> bool:
    """Detect whether existing certificate is a self-signed certificate."""
    if not CERT_FILE.exists():
        return False

    meta = _load_meta()
    if meta.get("email") == "self-signed":
        return True

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout", "-issuer", "-subject"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if proc.returncode == 0:
            lines = proc.stdout.splitlines()
            issuer = subject = ""
            for line in lines:
                if line.startswith("issuer="):
                    issuer = line.split("=", 1)[1].strip()
                elif line.startswith("subject="):
                    subject = line.split("=", 1)[1].strip()

            if issuer == subject or "Console-Web" in issuer or "Self-Signed" in issuer or "自签名" in issuer:
                return True
    except Exception as e:
        logger.warning("Error checking if cert is self-signed: %s", e)

    return False


def get_cert_status() -> dict:
    """Return current certificate status dict. Deletes self-signed cert if detected."""
    if is_self_signed_cert():
        logger.warning("get_cert_status: Self-signed certificate detected. Removing it to re-trigger ACME issuance...")
        remove_cert_files()

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        return {
            "has_cert": False,
            "status": "未开启 SSL / 等待 ACME 重新申请",
            "days_left": 0,
            "domain": None,
            "issuer": None,
            "expires_on": None,
        }

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout",
             "-enddate", "-issuer", "-subject"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if proc.returncode == 0:
            lines = proc.stdout.splitlines()
            enddate_str = issuer_str = subject_str = ""
            for line in lines:
                if line.startswith("notAfter="):
                    enddate_str = line.split("=", 1)[1]
                elif line.startswith("issuer="):
                    issuer_str = line.split("=", 1)[1]
                elif line.startswith("subject="):
                    subject_str = line.split("=", 1)[1]

            if enddate_str:
                try:
                    exp_dt = datetime.strptime(
                        enddate_str.strip(), "%b %d %H:%M:%S %Y GMT"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (exp_dt - datetime.now(timezone.utc)).days

                    domain_name = "N/A"
                    for prefix in ("CN = ", "CN="):
                        if prefix in subject_str:
                            domain_name = subject_str.split(prefix)[1].split("/")[0].strip()
                            break

                    issuer_name = "ACME SSL"
                    if "ZeroSSL" in issuer_str:
                        issuer_name = "ZeroSSL"
                    elif "Let's Encrypt" in issuer_str:
                        issuer_name = "Let's Encrypt"
                    else:
                        issuer_name = issuer_str or "ACME CA"

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


def _cert_is_valid(min_days: int = 7) -> bool:
    """Return True if a valid ACME cert exists with at least `min_days` remaining."""
    if is_self_signed_cert():
        return False
    status = get_cert_status()
    return status["has_cert"] and status["days_left"] > min_days


def get_acme_cmd():
    if shutil.which("acme.sh"):
        return ["acme.sh"]
    for p in [
        ACME_SH_PATH,
        Path("/root/.acme.sh/acme.sh"),
        Path("/usr/local/bin/acme.sh"),
        Path("/usr/bin/acme.sh"),
        Path.home() / ".acme.sh" / "acme.sh",
    ]:
        if p.exists():
            return [str(p)]
    return None


def ensure_acme_sh() -> bool:
    if get_acme_cmd() is not None:
        return True

    logger.info("Installing acme.sh tool via git/curl fallbacks...")
    acme_dir = Path.home() / ".acme.sh"
    acme_dir.mkdir(parents=True, exist_ok=True)

    # Strategy 1: Git clone from GitHub or Gitee mirror
    for repo_url in [
        "https://github.com/acmesh-official/acme.sh.git",
        "https://gitee.com/neilpang/acme.sh.git",
    ]:
        try:
            tmp_src = Path("/tmp/acme-src-runtime")
            if tmp_src.exists():
                shutil.rmtree(tmp_src, ignore_errors=True)
            logger.info("Cloning acme.sh from %s ...", repo_url)
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(tmp_src)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            )
            if proc.returncode == 0 and (tmp_src / "acme.sh").exists():
                subprocess.run(
                    ["sh", str(tmp_src / "acme.sh"), "--install",
                     "--home", str(acme_dir), "--config-home", str(acme_dir)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                shutil.rmtree(tmp_src, ignore_errors=True)
                if get_acme_cmd() is not None:
                    logger.info("acme.sh installed successfully via git clone!")
                    return True
        except Exception as e:
            logger.warning("Git clone acme.sh failed from %s: %s", repo_url, e)

    # Strategy 2: Direct curl installer script
    try:
        proc = subprocess.run(
            ["curl", "-fsSL", "https://get.acme.sh", "-o", "/tmp/install_acme.sh"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20,
        )
        if proc.returncode == 0:
            subprocess.run(
                ["sh", "/tmp/install_acme.sh", "--install-online", "-m", "admin@console-web.local"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if get_acme_cmd() is not None:
                logger.info("acme.sh installed successfully via curl!")
                return True
    except Exception as e:
        logger.warning("Failed to install acme.sh via curl: %s", e)

    return get_acme_cmd() is not None


def _detect_public_ip() -> str:
    """Detect public IP from multiple sources."""
    for url in ["https://ifconfig.me", "https://api64.ipify.org", "https://icanhazip.com"]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return socket.gethostname()


def issue_cert(target=None, email=None) -> tuple:
    """Issue a new ACME certificate via acme.sh (ZeroSSL / Let's Encrypt). Strictly NO self-signed fallback."""
    with _acme_lock:
        ensure_dirs()
        if is_self_signed_cert():
            logger.warning("issue_cert: Deleting legacy self-signed cert before issuing ACME cert...")
            remove_cert_files()

        if not target:
            target = _detect_public_ip()

        # Fix: Ensure email domain part is NOT a raw IP address (e.g. admin@37.114.48.47), which ZeroSSL API rejects
        if not email or "@" not in email or email.split("@")[-1].replace(".", "").isdigit():
            email = "admin@console-web.org"
        logger.info("ACME issue starting for target=%s, email=%s", target, email)

        acme_cmd = get_acme_cmd()
        if not acme_cmd:
            ensure_acme_sh()
            acme_cmd = get_acme_cmd()

        if not acme_cmd:
            return False, "未能安装或找到 acme.sh 工具，请检查系统环境"

        try:
            is_ip = target.replace(".", "").isdigit() or ":" in target

            # Case A: Target is an IP address -> Use Let's Encrypt with shortlived certificate profile
            if is_ip:
                logger.info("Target %s is an IP address, registering Let's Encrypt account and using shortlived profile...", target)
                subprocess.run(
                    [*acme_cmd, "--register-account", "-m", email, "--server", "letsencrypt"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                ip_issue_args = [
                    *acme_cmd, "--issue",
                    "-d", target,
                    "-w", str(CERTS_DIR),
                    "--server", "letsencrypt",
                    "--cert-profile", "shortlived",
                    "--force",
                ]
                proc = subprocess.run(ip_issue_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                logger.info("acme.sh IP issue output: %s", proc.stdout)

                if proc.returncode == 0:
                    install_proc = subprocess.run(
                        [*acme_cmd, "--install-cert", "-d", target,
                         "--cert-file", str(CERT_FILE),
                         "--key-file", str(KEY_FILE),
                         "--fullchain-file", str(CERT_FILE)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                    )
                    if install_proc.returncode == 0:
                        _save_meta(target, email)
                        logger.info("ACME Let's Encrypt IP certificate issued successfully for %s", target)
                        return True, f"成功为 IP 地址 {target} 签发并安装 Let's Encrypt 官方 ACME SSL 证书！"

                return False, f"IP 证书签发失败，请确认 80 端口可被外网访问 (详细: {proc.stdout[:140]})"

            # Case B: Target is a domain name -> Try ZeroSSL first, then Let's Encrypt fallback
            reg_proc = subprocess.run(
                [*acme_cmd, "--register-account", "-m", email, "--server", "zerossl"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            logger.info("ZeroSSL account registration output: %s", reg_proc.stdout)

            issue_args = [
                *acme_cmd, "--issue",
                "-d", target,
                "-w", str(CERTS_DIR),
                "--server", "zerossl",
                "--force",
            ]
            proc = subprocess.run(
                issue_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            logger.info("acme.sh issue output: %s", proc.stdout)

            if proc.returncode == 0:
                install_args = [
                    *acme_cmd, "--install-cert",
                    "-d", target,
                    "--cert-file", str(CERT_FILE),
                    "--key-file", str(KEY_FILE),
                    "--fullchain-file", str(CERT_FILE),
                ]
                install_proc = subprocess.run(
                    install_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                if install_proc.returncode == 0:
                    _save_meta(target, email)
                    logger.info("ACME ZeroSSL certificate issued successfully for %s", target)
                    return True, f"成功为 {target} 签发并安装官方 ACME SSL 证书！"

            # If ZeroSSL fails, attempt backup via Let's Encrypt ACME server
            logger.info("ZeroSSL issue returned %d, attempting backup via Let's Encrypt...", proc.returncode)
            le_args = [
                *acme_cmd, "--issue",
                "-d", target,
                "-w", str(CERTS_DIR),
                "--server", "letsencrypt",
                "--force",
            ]
            le_proc = subprocess.run(
                le_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            if le_proc.returncode == 0:
                install_proc = subprocess.run(
                    [*acme_cmd, "--install-cert", "-d", target,
                     "--cert-file", str(CERT_FILE),
                     "--key-file", str(KEY_FILE),
                     "--fullchain-file", str(CERT_FILE)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                if install_proc.returncode == 0:
                    _save_meta(target, email)
                    logger.info("ACME Let's Encrypt certificate issued successfully for %s", target)
                    return True, f"成功为 {target} 签发 Let's Encrypt ACME 证书！"

            return False, f"ACME 官方证书签发失败，请确认 80 端口可被外网访问 (详细: {proc.stdout[:120]})"
        except Exception as e:
            logger.exception("ACME issuance exception: %s", e)
            return False, f"ACME 证书签发发生错误: {e}"


def renew_cert() -> tuple:
    """Renew existing ACME certificate."""
    with _acme_lock:
        if is_self_signed_cert():
            remove_cert_files()
            return issue_cert()

        acme_cmd = get_acme_cmd()
        meta = _load_meta()
        target = meta.get("target") or _detect_public_ip()

        if acme_cmd and target:
            logger.info("Renewing ACME certificate for %s ...", target)
            proc = subprocess.run(
                [*acme_cmd, "--renew", "-d", target, "--force"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            if proc.returncode == 0:
                subprocess.run(
                    [*acme_cmd, "--install-cert", "-d", target,
                     "--cert-file", str(CERT_FILE),
                     "--key-file", str(KEY_FILE),
                     "--fullchain-file", str(CERT_FILE)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                logger.info("ACME certificate renewed successfully")
                return True, "ACME 官方 SSL 证书自动续期成功！"

        return issue_cert(target=target)


def _auto_init():
    """Startup check: clean self-signed certs and request official ACME cert."""
    logger.info("ACME auto-init: checking existing certificate...")

    if is_self_signed_cert():
        logger.warning("Detected self-signed cert on startup. Deleting it to re-trigger ACME issuance...")
        remove_cert_files()

    if _cert_is_valid(min_days=7):
        status = get_cert_status()
        logger.info(
            "ACME auto-init: valid ACME certificate found for %s (%s days left).",
            status.get("domain"), status.get("days_left"),
        )
        return

    logger.info("ACME auto-init: no valid ACME certificate found. Initiating auto-issuance...")
    try:
        ok, msg = issue_cert()
        logger.info("ACME auto-init result: %s", msg)
    except Exception as e:
        logger.exception("ACME auto-init error: %s", e)


def _auto_renew_loop():
    """Daemon thread."""
    time.sleep(5)
    try:
        _auto_init()
    except Exception as e:
        logger.exception("ACME auto-init error: %s", e)

    while True:
        try:
            time.sleep(43200)  # 12 hours
            status = get_cert_status()
            if not status["has_cert"]:
                issue_cert()
            elif status["days_left"] <= 30:
                renew_cert()
        except Exception as e:
            logger.exception("ACME daemon error: %s", e)


def start_daemon():
    t = threading.Thread(target=_auto_renew_loop, daemon=True, name="ACME-AutoRenew")
    t.start()


if __name__ == "__main__":
    import sys
    print("==================================================")
    print("🔒 ACME 官方 SSL 证书检测与申请管理 (只申请官方证书)")
    print("==================================================")

    if is_self_signed_cert():
        print("⚠️ 检测到本地残留的自签名证书，正在自动清理并重新发起 ACME 官方证书申请...")
        remove_cert_files()

    status = get_cert_status()
    if not status.get("has_cert") or status.get("days_left", 0) <= 7:
        print("🔍 未检测到有效官方 ACME 证书，正在自动触发 ACME / ZeroSSL 证书申请...")
        ok, msg = issue_cert()
        print(f"👉 结果: {msg}")
        status = get_cert_status()
    else:
        print("✅ 检测到有效官方 ACME SSL 证书，状态良好。")

    print("\n--- ACME / SSL 证书运行状态 ---")
    print(f"域名 / IP:  {status.get('domain', 'N/A')}")
    print(f"签发机构:   {status.get('issuer', 'N/A')}")
    print(f"剩余有效:   {status.get('days_left', 0)} 天")
    print(f"到期时间:   {status.get('expires_on', 'N/A')}")
    print(f"当前状态:   {status.get('status', 'N/A')}")
    print("==================================================")

    if status.get("has_cert"):
        sys.exit(0)
    else:
        sys.exit(1)
