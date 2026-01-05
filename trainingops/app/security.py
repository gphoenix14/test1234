import os
import re
import json
import uuid
import html as _html
import secrets
import unicodedata
import urllib.request
import urllib.error
from datetime import datetime, timedelta, date, time
from typing import Optional, Dict, List, Set, Tuple

from flask import request, abort, current_app, send_file
from werkzeug.utils import secure_filename

from .extensions import db
from .models import User, Docente, Evento, Incarico, Calendario, event_docente

COMMON_PASSWORDS = {
    "password", "password1", "password123", "qwerty", "qwerty123", "12345678", "123456789",
    "admin", "admin123", "welcome", "welcome123", "letmein", "changeme",
    "abcdefg", "abcdefg1", "iloveyou", "ciao123", "test1234"
}

REGIME_IVA_CHOICES = [
    "Partita Iva in Regime dei minimi / agevolato / forfettario",
    "R.A. secca",
    "P.I. senza R.A. (es: ditta individuale, srl, spa...)",
    "P.I. in ritenuta d'acconto (consulenti)",
]

ALLOWED_CV_EXT = {"pdf"}

IT_DATA_DIR_DEFAULT = "data"
COMUNI_SOURCE_URL = "https://raw.githubusercontent.com/matteocontrini/comuni-json/master/comuni.json"

_COMUNI_CACHE = None
_PROVINCE_CACHE = None

AUDIT_LOG_PATH_DEFAULT = "audit.log"

def audit(event: str, message: str = "", actor=None, meta: Optional[dict] = None):
    """
    Audit JSONL minimalista. Non deve rompere mai il flusso.
    """
    try:
        actor_payload = None
        if actor is not None:
            actor_payload = {
                "id": getattr(actor, "id", None),
                "username": getattr(actor, "username", None),
                "role": getattr(actor, "role", None),
                "status": getattr(actor, "status", None),
            }

        req_payload = None
        try:
            req_payload = {
                "path": getattr(request, "path", None),
                "method": getattr(request, "method", None),
                "remote_addr": getattr(request, "remote_addr", None),
                "user_agent": str(getattr(request, "user_agent", "")) if getattr(request, "user_agent", None) else None,
            }
        except Exception:
            req_payload = None

        payload = {
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "event": (event or "").strip()[:120],
            "message": (message or "").strip()[:2000],
            "actor": actor_payload,
            "request": req_payload,
            "meta": meta or None,
        }

        line = json.dumps(payload, ensure_ascii=False)

        current_app.logger.info(line)

        audit_path = current_app.config.get("AUDIT_LOG_PATH") or os.path.join(current_app.instance_path, AUDIT_LOG_PATH_DEFAULT)
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        try:
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    except Exception:
        pass

def validate_piva(piva: str) -> Optional[str]:
    piva = (piva or "").strip()
    if not piva:
        return None
    if not re.fullmatch(r"\d{11}", piva):
        return "Partita IVA non valida (attese 11 cifre)."
    return None

def validate_password_policy(pwd: str) -> Optional[str]:
    pwd = pwd or ""

    if len(pwd) < 8:
        return "La password deve essere lunga almeno 8 caratteri."
    if len(pwd) > 128:
        return "La password è troppo lunga (max 128 caratteri)."
    if any(ch.isspace() for ch in pwd):
        return "La password non deve contenere spazi."

    lower = any("a" <= ch <= "z" for ch in pwd)
    upper = any("A" <= ch <= "Z" for ch in pwd)
    digit = any(ch.isdigit() for ch in pwd)
    special = any(not ch.isalnum() for ch in pwd)

    if not lower:
        return "La password deve contenere almeno una lettera minuscola."
    if not upper:
        return "La password deve contenere almeno una lettera maiuscola."
    if not digit:
        return "La password deve contenere almeno un numero."
    if not special:
        return "La password deve contenere almeno un carattere speciale (es. !, ?, @, #, _)."

    normalized = pwd.strip().lower()
    if normalized in COMMON_PASSWORDS:
        return "Password troppo comune. Scegline una più robusta."

    if re.search(r"(.)\1\1\1", pwd):
        return "Password troppo debole: evita 4 o più caratteri identici consecutivi."

    return None

def allowed_pdf(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower().strip()
    return ext in ALLOWED_CV_EXT

def _is_pdf_magic(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(5)
        return head == b"%PDF-"
    except Exception:
        return False

def save_cv_pdf(file_storage, docente_id: int) -> str:
    """
    Upload sicuro: estensione + mimetype best-effort + magic bytes PDF.
    """
    if not file_storage:
        raise ValueError("File CV mancante")

    original = file_storage.filename or ""
    if not allowed_pdf(original):
        raise ValueError("CV non valido: carica un PDF")

    ctype = (file_storage.mimetype or "").lower()
    if ctype and "pdf" not in ctype:
        if ctype not in ("application/octet-stream",):
            raise ValueError("CV non valido: MIME type non PDF")

    safe = secure_filename(original)
    if not safe.lower().endswith(".pdf"):
        safe = f"{safe}.pdf"

    upload_root = current_app.config["UPLOAD_ROOT"]
    cv_folder = os.path.join(upload_root, "cv")
    os.makedirs(cv_folder, exist_ok=True)

    unique_name = f"docente_{docente_id}_{uuid.uuid4().hex}.pdf"
    path = os.path.join(cv_folder, unique_name)

    file_storage.save(path)

    # Check magic bytes
    if not _is_pdf_magic(path):
        try:
            os.remove(path)
        except Exception:
            pass
        raise ValueError("CV non valido: contenuto non PDF")

    return unique_name

def send_docente_cv_file(docente: Docente, download: bool):
    """
    Serve CV evitando traversal e vincolando pattern filename.
    """
    if not docente.cv_filename:
        abort(404)

    # vincolo: docente_<id>_....pdf
    if not re.fullmatch(rf"docente_{docente.id}_[a-f0-9]{{32}}\.pdf", docente.cv_filename or ""):
        abort(404)

    upload_root = current_app.config["UPLOAD_ROOT"]
    cv_folder = os.path.join(upload_root, "cv")
    path = os.path.join(cv_folder, docente.cv_filename)

    if not os.path.isfile(path):
        abort(404)

    # inline vs attachment
    as_attachment = bool(download)
    return send_file(path, as_attachment=as_attachment, download_name=f"CV_{docente.display_name}.pdf")

def parse_dt_local(dt_str: str) -> datetime:
    if not dt_str:
        raise ValueError("Datetime mancante")
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            pass
    raise ValueError("Formato datetime non valido (atteso YYYY-MM-DDTHH:MM)")

def parse_date(d_str: str) -> date:
    if not d_str:
        raise ValueError("Data mancante")
    try:
        return datetime.strptime(d_str, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError("Formato data non valido (atteso YYYY-MM-DD)")

def parse_time(t_str: str) -> time:
    if not t_str:
        raise ValueError("Ora mancante")
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(t_str, fmt).time()
        except ValueError:
            pass
    raise ValueError("Formato ora non valido (atteso HH:MM)")

def hours_between(a: datetime, b: datetime) -> float:
    return max(0.0, (b - a).total_seconds() / 3600.0)

def ensure_calendar_for_incarico(incarico: Incarico):
    if incarico.calendario is None:
        incarico.calendario = Calendario(timezone="Europe/Rome")
        db.session.add(incarico.calendario)
        db.session.commit()

def intervals_overlap(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> bool:
    return a_start < b_end and a_end > b_start

def docente_has_conflict(docente_id: int, start_dt: datetime, end_dt: datetime, exclude_event_ids: Optional[List[int]] = None) -> List[Evento]:
    q = (
        Evento.query
        .join(event_docente, event_docente.c.evento_id == Evento.id)
        .filter(event_docente.c.docente_id == docente_id)
        .filter(Evento.start_dt < end_dt, Evento.end_dt > start_dt)
    )
    if exclude_event_ids:
        q = q.filter(~Evento.id.in_(exclude_event_ids))
    return q.all()

def validate_docenti_no_overlap(docente_ids: List[int], start_dt: datetime, end_dt: datetime, exclude_event_ids: Optional[List[int]] = None) -> Dict[int, List[Evento]]:
    conflicts: Dict[int, List[Evento]] = {}
    for did in docente_ids:
        c = docente_has_conflict(did, start_dt, end_dt, exclude_event_ids=exclude_event_ids)
        if c:
            conflicts[did] = c
    return conflicts

def conflicts_to_message(conflicts: Dict[int, List[Evento]]) -> str:
    if not conflicts:
        return ""
    parts = ["Vincolo docenti: assegnazione/modifica impossibile per sovrapposizione eventi."]
    for did, evs in conflicts.items():
        d = db.session.get(Docente, did)
        dname = d.display_name if d else f"Docente {did}"
        parts.append(f"- {dname}:")
        for e in evs[:10]:
            parts.append(f"  * Evento ID {e.id} ({e.incarico.titolo}) {e.start_dt.strftime('%Y-%m-%d %H:%M')} - {e.end_dt.strftime('%Y-%m-%d %H:%M')}")
        if len(evs) > 10:
            parts.append(f"  * ... (+{len(evs) - 10} altri)")
    return "\n".join(parts)

def incarico_stats(incarico_id: int) -> dict:
    eventi = Evento.query.filter_by(incarico_id=incarico_id).all()
    opt_hours = 0.0
    conf_hours = 0.0
    opt_count = 0
    conf_count = 0
    for e in eventi:
        h = hours_between(e.start_dt, e.end_dt)
        if e.status == "Confermato":
            conf_hours += h
            conf_count += 1
        else:
            opt_hours += h
            opt_count += 1
    return {
        "opzionate_ore": opt_hours,
        "confermate_ore": conf_hours,
        "opzionate_count": opt_count,
        "confermate_count": conf_count,
        "totale_count": len(eventi),
        "totale_ore": opt_hours + conf_hours
    }

def parse_int_or_none(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None

def _normalize_username_part(s: str) -> str:
    s = (s or "").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^a-z0-9]+", ".", s)
    s = re.sub(r"\.+", ".", s).strip(".")
    return s

def generate_unique_username(nome: str, cognome: str, max_tries: int = 50) -> str:
    base_n = _normalize_username_part(nome)
    base_c = _normalize_username_part(cognome)
    base = f"{base_n}.{base_c}".strip(".")
    if not base or base == ".":
        base = "docente"

    for _ in range(max_tries):
        suffix = secrets.randbelow(9000) + 1000
        candidate = f"{base}{suffix}"
        if not User.query.filter_by(username=candidate).first():
            return candidate

    return f"{base}{secrets.token_hex(3)}"

def _build_luogo(comune: str, prov: str) -> str:
    comune = (comune or "").strip()
    prov = (prov or "").strip().upper()
    if comune and prov:
        return f"{comune} ({prov})"
    return comune

def generate_invite_code() -> str:
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10]

def ensure_comuni_dataset_loaded() -> Tuple[list, list]:
    """
    Nota sicurezza (OWASP SSRF): URL è hardcoded e non controllabile dall'utente.
    In produzione, preferibile vendorizzare il JSON e aggiornarlo offline.
    """
    global _COMUNI_CACHE, _PROVINCE_CACHE

    if _COMUNI_CACHE is not None and _PROVINCE_CACHE is not None:
        return _COMUNI_CACHE, _PROVINCE_CACHE

    base_dir = current_app.root_path
    data_dir = os.path.join(base_dir, IT_DATA_DIR_DEFAULT)
    cache_path = os.path.join(data_dir, "comuni.json")
    os.makedirs(data_dir, exist_ok=True)

    if not os.path.isfile(cache_path):
        try:
            req = urllib.request.Request(
                COMUNI_SOURCE_URL,
                headers={"User-Agent": "TrainingOpsSimple/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                if getattr(resp, "status", 200) != 200:
                    raise RuntimeError(f"HTTP {getattr(resp, 'status', '??')}")
                raw = resp.read().decode("utf-8", errors="replace")
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(raw)
        except Exception:
            _COMUNI_CACHE, _PROVINCE_CACHE = [], []
            return _COMUNI_CACHE, _PROVINCE_CACHE

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            comuni = json.load(f)
    except Exception:
        _COMUNI_CACHE, _PROVINCE_CACHE = [], []
        return _COMUNI_CACHE, _PROVINCE_CACHE

    normalized = []
    provinces_map = {}
    for c in comuni or []:
        nome = (c.get("nome") or "").strip()
        prov = c.get("provincia") or {}
        sigla = (prov.get("sigla") or "").strip().upper()
        prov_nome = (prov.get("nome") or "").strip()

        if not nome or not sigla:
            continue

        normalized.append({
            "nome": nome,
            "prov_sigla": sigla,
            "prov_nome": prov_nome or sigla,
        })
        provinces_map[sigla] = prov_nome or sigla

    provinces = [{"code": k, "name": v} for k, v in provinces_map.items()]
    provinces.sort(key=lambda x: (x["name"] or "", x["code"] or ""))

    _COMUNI_CACHE = normalized
    _PROVINCE_CACHE = provinces
    return _COMUNI_CACHE, _PROVINCE_CACHE

def nl2br_safe(text: str) -> str:
    """
    Mitigazione XSS: escape + newline -> <br>.
    Usare nei template per campi note.
    """
    text = text or ""
    esc = _html.escape(text)
    return esc.replace("\n", "<br>\n")

def canonical_host_check_or_abort():
    """
    Mitigazione OWASP: Host header / CSRF origin checks.
    """
    canon = (current_app.config.get("CANONICAL_HOST") or "").strip().lower()
    if not canon:
        return

    host = (request.host.split(":")[0] if request.host else "").strip().lower()
    if host and host != canon:
        abort(400)

def csrf_origin_referer_check_or_abort():
    """
    CSRF senza token (compatibile con template legacy):
    - per metodi state-changing, richiede Origin/Referer same-origin (o canonical host).
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # permetti API JSON se usi token/Authorization (non implementato qui); per ora applichiamo sempre.
    origin = (request.headers.get("Origin") or "").strip()
    referer = (request.headers.get("Referer") or "").strip()

    canon = (current_app.config.get("CANONICAL_HOST") or "").strip().lower()
    allowed_host = canon if canon else (request.host.split(":")[0].lower() if request.host else "")

    def _host_from_url(url: str) -> str:
        # parse minimale
        m = re.match(r"^https?://([^/]+)/?", url, re.IGNORECASE)
        if not m:
            return ""
        hostport = m.group(1)
        return hostport.split(":")[0].lower().strip()

    if origin:
        if _host_from_url(origin) != allowed_host:
            abort(403)
        return

    if referer:
        if _host_from_url(referer) != allowed_host:
            abort(403)
        return

    # se mancano entrambi (alcuni client), blocca per sicurezza
    abort(403)

def lockout_check(user: User) -> Optional[str]:
    """
    Controllo lock temporaneo (bruteforce hardening).
    """
    if not user:
        return None
    if user.locked_until and datetime.utcnow() < user.locked_until:
        return "Account temporaneamente bloccato. Riprova più tardi."
    return None

def register_failed_login(user: Optional[User]):
    """
    Registra fallimento: incrementa contatore e attiva lock temporaneo.
    """
    if not user:
        return
    now = datetime.utcnow()
    user.failed_login_count = (user.failed_login_count or 0) + 1
    user.last_failed_login_at = now

    # policy: 10 errori => lock 15 minuti
    if user.failed_login_count >= 10:
        user.locked_until = now + timedelta(minutes=15)
        user.failed_login_count = 0  # reset dopo lock

    db.session.commit()

def register_success_login(user: User):
    if not user:
        return
    user.failed_login_count = 0
    user.last_failed_login_at = None
    user.locked_until = None
    db.session.commit()

def require_docente_owns_incarico(docente_id: int, incarico_id: int):
    """
    Anti-IDOR: il docente può vedere solo incarichi dove ha eventi assegnati.
    """
    count = (
        Evento.query
        .join(event_docente, event_docente.c.evento_id == Evento.id)
        .filter(Evento.incarico_id == incarico_id, event_docente.c.docente_id == docente_id)
        .count()
    )
    if count == 0:
        abort(403)
