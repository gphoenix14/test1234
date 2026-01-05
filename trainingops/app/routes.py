import uuid
import secrets
import re
from datetime import datetime, timedelta, date
from typing import List, Dict, Set, Tuple, Optional

from flask import (
    Blueprint, current_app, request, redirect, url_for, render_template, flash, jsonify, abort
)
from flask_login import login_user, logout_user, login_required, current_user

from .extensions import db, login_manager, limiter
from .models import User, Invite, Cliente, Incarico, Evento, Docente, event_docente
from .security import (
    REGIME_IVA_CHOICES,
    validate_password_policy, validate_piva,
    parse_date, parse_time, parse_dt_local,
    save_cv_pdf, audit,
    ensure_calendar_for_incarico,
    docente_has_conflict, validate_docenti_no_overlap,
    conflicts_to_message, incarico_stats,
    parse_int_or_none, intervals_overlap,
    generate_unique_username, _build_luogo,
    ensure_comuni_dataset_loaded,
    send_docente_cv_file,
    lockout_check, register_failed_login, register_success_login,
    require_docente_owns_incarico
)

bp = Blueprint("main", __name__)
auth = Blueprint("auth", __name__)
admin = Blueprint("admin", __name__)
docente_bp = Blueprint("docente", __name__)
api = Blueprint("api", __name__)

# =========================
# Auth / role helpers
# =========================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def role_required(role: str):
    def deco(fn):
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role:
                abort(403)
            if not current_user.is_active_account:
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco

# =========================
# Public index
# =========================

@bp.route("/")
@login_required
def index():
    if not current_user.is_active_account:
        flash("Account non attivo. Contatta l'amministratore.", "danger")
        logout_user()
        return redirect(url_for("auth.login"))

    if current_user.role == "admin":
        return redirect(url_for("admin.admin_clients"))
    return redirect(url_for("docente.docente_dashboard"))

# =========================
# Login/Logout
# =========================

@auth.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config.get("LIMITER_LOGIN", "8 per minute"))
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()

        # lockout check
        if user:
            msg = lockout_check(user)
            if msg:
                audit("login_locked", f"user={username}")
                flash(msg, "danger")
                return redirect(url_for("auth.login"))

        if not user or not user.check_password(password):
            if user:
                register_failed_login(user)
            audit("login_failed", f"user={username}")
            flash("Credenziali non valide", "danger")
            return redirect(url_for("auth.login"))

        if user.status != "active":
            if user.status == "pending":
                flash("Account registrato. In attesa di sblocco da parte dell'amministratore.", "warning")
            else:
                flash("Account disabilitato. Contatta l'amministratore.", "danger")
            audit("login_denied_status", f"user={username} status={user.status}")
            return redirect(url_for("auth.login"))

        register_success_login(user)
        login_user(user)
        audit("login_ok", f"user={username}", actor=user)
        return redirect(url_for("main.index"))

    return render_template("login.html", app_name=current_app.config["APP_NAME"])

@auth.route("/logout")
@login_required
def logout():
    audit("logout", f"user={getattr(current_user, 'username', None)}", actor=current_user)
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route("/account/password", methods=["GET", "POST"])
@login_required
@limiter.limit(lambda: current_app.config.get("LIMITER_SENSITIVE", "30 per minute"))
def account_change_password():
    if not current_user.is_active_account:
        abort(403)

    if request.method == "POST":
        cur = request.form.get("current_password") or ""
        new1 = request.form.get("new_password") or ""
        new2 = request.form.get("new_password2") or ""

        if not current_user.check_password(cur):
            audit("pwd_change_failed_current", actor=current_user)
            flash("Password attuale non corretta", "danger")
            return redirect(url_for("auth.account_change_password"))

        msg = validate_password_policy(new1)
        if msg:
            flash(msg, "danger")
            return redirect(url_for("auth.account_change_password"))

        if new1 != new2:
            flash("Le nuove password non coincidono", "danger")
            return redirect(url_for("auth.account_change_password"))

        current_user.set_password(new1)
        db.session.commit()
        audit("pwd_change_ok", actor=current_user)
        flash("Password aggiornata", "success")
        return redirect(url_for("main.index"))

    return render_template("account_password.html", app_name=current_app.config["APP_NAME"])

# =========================
# API Italy
# =========================

@api.route("/api/italy/province")
@limiter.limit("60 per minute")
def api_italy_province():
    _, prov = ensure_comuni_dataset_loaded()
    return jsonify(prov)

@api.route("/api/italy/comuni")
@limiter.limit("120 per minute")
def api_italy_comuni():
    comuni, _ = ensure_comuni_dataset_loaded()

    q = (request.args.get("q") or "").strip().lower()
    prov = (request.args.get("prov") or "").strip().upper()
    limit_s = (request.args.get("limit") or "").strip()
    try:
        limit = int(limit_s) if limit_s else 25
    except ValueError:
        limit = 25
    limit = max(1, min(50, limit))

    if not comuni or len(q) < 2:
        return jsonify([])

    out = []
    for c in comuni:
        if prov and c["prov_sigla"] != prov:
            continue
        nome_l = c["nome"].lower()
        if q not in nome_l:
            continue
        out.append({
            "name": c["nome"],
            "prov": c["prov_sigla"],
            "prov_name": c["prov_nome"],
        })
        if len(out) >= limit:
            break

    return jsonify(out)

# =========================
# Invite registration (Public)
# =========================

@auth.route("/invite/<string:token>", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config.get("LIMITER_INVITE", "10 per hour"))
def invite_register(token: str):
    inv = Invite.query.filter_by(token=token).first()
    if not inv:
        flash("Invito non valido", "danger")
        return redirect(url_for("auth.login"))

    if inv.is_used:
        flash("Invito già utilizzato", "danger")
        return redirect(url_for("auth.login"))

    if inv.is_expired:
        flash("Invito scaduto", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("invite_code") or "").strip()
        if code != inv.code:
            audit("invite_code_wrong", f"invite_id={inv.id}")
            flash("Codice invito non corretto", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        email = (request.form.get("email") or "").strip() or None
        pwd1 = request.form.get("password") or ""
        pwd2 = request.form.get("password2") or ""

        regime_iva = (request.form.get("regime_iva") or "").strip()
        if regime_iva not in REGIME_IVA_CHOICES:
            flash("Seleziona un Regime IVA / Tipo P.IVA valido.", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        tipo_soggetto = (request.form.get("tipo_soggetto") or "Libero Professionista").strip()
        if tipo_soggetto not in ("Azienda", "Libero Professionista"):
            tipo_soggetto = "Libero Professionista"

        nome = (request.form.get("nome") or "").strip()
        cognome = (request.form.get("cognome") or "").strip()
        sesso = (request.form.get("sesso") or "").strip() or None
        cf = (request.form.get("codice_fiscale") or "").strip() or None
        rag_soc = (request.form.get("ragione_sociale") or "").strip() or None
        piva = (request.form.get("partita_iva") or "").strip() or None

        banca = (request.form.get("banca_appoggio") or "").strip() or None
        intest = (request.form.get("intestatario_banca") or "").strip() or None
        iban = (request.form.get("iban") or "").strip() or None
        bic = (request.form.get("bic_swift") or "").strip() or None

        data_nascita_s = (request.form.get("data_nascita") or "").strip()
        nascita_comune = (request.form.get("luogo_nascita_comune") or "").strip()
        nascita_prov = (request.form.get("luogo_nascita_provincia") or "").strip().upper()
        luogo_nascita = _build_luogo(nascita_comune, nascita_prov)

        res_via = (request.form.get("res_via") or "").strip()
        res_civico = (request.form.get("res_civico") or "").strip()
        res_comune = (request.form.get("res_comune") or "").strip()
        res_cap = (request.form.get("res_cap") or "").strip()
        res_provincia = (request.form.get("res_provincia") or "").strip().upper()
        res_nazione = (request.form.get("res_nazione") or "").strip() or "Italia"

        if not nome or not cognome:
            flash("Nome e Cognome sono obbligatori", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if tipo_soggetto == "Azienda" and not rag_soc:
            flash("Ragione sociale obbligatoria per il tipo soggetto Azienda.", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        msg = validate_password_policy(pwd1)
        if msg:
            flash(msg, "danger")
            return redirect(url_for("auth.invite_register", token=token))
        if pwd1 != pwd2:
            flash("Le password non coincidono", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if not data_nascita_s:
            flash("Data di nascita obbligatoria", "danger")
            return redirect(url_for("auth.invite_register", token=token))
        try:
            data_nascita = parse_date(data_nascita_s)
        except ValueError:
            flash("Formato data di nascita non valido", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if not nascita_comune:
            flash("Comune di nascita obbligatorio", "danger")
            return redirect(url_for("auth.invite_register", token=token))
        if not nascita_prov or not re.fullmatch(r"[A-Z]{2}", nascita_prov):
            flash("Provincia di nascita non valida (attese 2 lettere, es. NA)", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if not (res_via and res_civico and res_comune and res_cap and res_provincia):
            flash("Residenza incompleta: via, civico, comune, CAP e provincia sono obbligatori", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if not re.fullmatch(r"\d{5}", res_cap):
            flash("CAP non valido (atteso 5 cifre)", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        if len(res_provincia) != 2 or not re.fullmatch(r"[A-Z]{2}", res_provincia):
            flash("Provincia non valida (attese 2 lettere, es. NA)", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        piva_required = (regime_iva != "R.A. secca")
        if piva_required and not piva:
            flash("Partita IVA obbligatoria per il regime selezionato.", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        piva_err = validate_piva(piva or "")
        if piva_err:
            flash(piva_err, "danger")
            return redirect(url_for("auth.invite_register", token=token))

        cv_file = request.files.get("cv_pdf")
        if not cv_file or not cv_file.filename:
            flash("Carica il CV in formato PDF (obbligatorio)", "danger")
            return redirect(url_for("auth.invite_register", token=token))

        username = generate_unique_username(nome, cognome)

        try:
            d = Docente(
                nome=nome,
                cognome=cognome,
                email=email,
                sesso=sesso,
                codice_fiscale=cf,
                tipo_soggetto=tipo_soggetto,
                ragione_sociale=rag_soc,
                regime_iva=regime_iva,
                partita_iva=piva,
                banca_appoggio=banca,
                intestatario_banca=intest,
                iban=iban,
                bic_swift=bic,
                data_nascita=data_nascita,
                luogo_nascita=luogo_nascita,
                res_via=res_via,
                res_civico=res_civico,
                res_comune=res_comune,
                res_cap=res_cap,
                res_provincia=res_provincia,
                res_nazione=res_nazione,
            )
            db.session.add(d)
            db.session.commit()

            cv_name = save_cv_pdf(cv_file, docente_id=d.id)
            d.cv_filename = cv_name
            d.cv_uploaded_at = datetime.utcnow()
            db.session.commit()

            u = User(username=username, role="docente", docente_id=d.id, status="pending")
            u.set_password(pwd1)
            db.session.add(u)
            db.session.commit()

            inv.used_at = datetime.utcnow()
            inv.used_by_user_id = u.id
            db.session.commit()

            audit("invite_register_ok", f"user={username} docente_id={d.id}", actor=u)
            flash("Registrazione completata. Account in attesa di sblocco da parte dell'amministratore.", "success")
            return redirect(url_for("auth.login"))

        except ValueError as ex:
            db.session.rollback()
            flash(str(ex), "danger")
            return redirect(url_for("auth.invite_register", token=token))
        except Exception as ex:
            db.session.rollback()
            audit("invite_register_error", str(ex))
            flash("Errore registrazione.", "danger")
            return redirect(url_for("auth.invite_register", token=token))

    return render_template(
        "invite_register.html",
        app_name=current_app.config["APP_NAME"],
        invite=inv,
        regime_iva_choices=REGIME_IVA_CHOICES,
        max_cv_mb=current_app.config["MAX_CV_MB"],
    )

# =========================
# Admin - Inviti
# =========================

@admin.route("/admin/inviti", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("120 per hour")
def admin_inviti():
    if request.method == "POST":
        code = secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10]
        token = uuid.uuid4().hex

        exp_days_s = (request.form.get("expiry_days") or "").strip()
        expires_at = None
        if exp_days_s:
            try:
                exp_days = int(exp_days_s)
                if exp_days > 0:
                    expires_at = datetime.utcnow() + timedelta(days=exp_days)
            except ValueError:
                pass

        inv = Invite(token=token, code=code, expires_at=expires_at)
        db.session.add(inv)
        db.session.commit()

        audit("admin_invite_create", f"invite_id={inv.id}", actor=current_user)
        flash("Invito creato", "success")
        return redirect(url_for("admin.admin_inviti"))

    inviti = Invite.query.order_by(Invite.id.desc()).all()
    return render_template("admin_inviti.html", app_name=current_app.config["APP_NAME"], inviti=inviti)

@admin.route("/admin/inviti/<int:invite_id>/revoke", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per hour")
def admin_inviti_revoke(invite_id: int):
    inv = db.session.get(Invite, invite_id) or abort(404)
    if inv.is_used:
        flash("Impossibile revocare: invito già utilizzato", "danger")
        return redirect(url_for("admin.admin_inviti"))
    db.session.delete(inv)
    db.session.commit()
    audit("admin_invite_revoke", f"invite_id={invite_id}", actor=current_user)
    flash("Invito revocato", "success")
    return redirect(url_for("admin.admin_inviti"))

# =========================
# Admin - Clienti/Incarichi
# =========================

@admin.route("/admin/clients")
@login_required
@role_required("admin")
def admin_clients():
    q = (request.args.get("q") or "").strip()
    query = Cliente.query
    if q:
        query = query.filter(Cliente.ragione_sociale.ilike(f"%{q}%"))
    clients = query.order_by(Cliente.ragione_sociale.asc()).all()
    return render_template("admin_clients.html", clients=clients, q=q, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/clients/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("120 per hour")
def admin_clients_new():
    if request.method == "POST":
        rs = (request.form.get("ragione_sociale") or "").strip()
        if not rs:
            flash("Ragione sociale obbligatoria", "danger")
            return redirect(url_for("admin.admin_clients_new"))
        c = Cliente(
            ragione_sociale=rs,
            email=(request.form.get("email") or "").strip() or None,
            telefono=(request.form.get("telefono") or "").strip() or None,
            note=(request.form.get("note") or "").strip() or None,
        )
        db.session.add(c)
        db.session.commit()
        audit("admin_client_create", f"client_id={c.id}", actor=current_user)
        flash("Cliente creato", "success")
        return redirect(url_for("admin.admin_client_detail", client_id=c.id))
    return render_template("admin_clients_new.html", app_name=current_app.config["APP_NAME"])

@admin.route("/admin/clients/<int:client_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("240 per hour")
def admin_client_detail(client_id):
    client = db.session.get(Cliente, client_id) or abort(404)
    if request.method == "POST":
        client.ragione_sociale = (request.form.get("ragione_sociale") or "").strip()
        client.email = (request.form.get("email") or "").strip() or None
        client.telefono = (request.form.get("telefono") or "").strip() or None
        client.note = (request.form.get("note") or "").strip() or None
        if not client.ragione_sociale:
            flash("Ragione sociale obbligatoria", "danger")
            return redirect(url_for("admin.admin_client_detail", client_id=client.id))
        db.session.commit()
        audit("admin_client_update", f"client_id={client.id}", actor=current_user)
        flash("Cliente aggiornato", "success")
        return redirect(url_for("admin.admin_client_detail", client_id=client.id))

    incarichi = Incarico.query.filter_by(cliente_id=client.id).order_by(Incarico.id.desc()).all()
    return render_template("admin_client_detail.html", client=client, incarichi=incarichi, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/clients/<int:client_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per hour")
def admin_client_delete(client_id):
    client = db.session.get(Cliente, client_id) or abort(404)
    db.session.delete(client)
    db.session.commit()
    audit("admin_client_delete", f"client_id={client_id}", actor=current_user)
    flash("Cliente eliminato", "success")
    return redirect(url_for("admin.admin_clients"))

@admin.route("/admin/clients/<int:client_id>/incarichi/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("120 per hour")
def admin_incarico_new(client_id):
    client = db.session.get(Cliente, client_id) or abort(404)
    if request.method == "POST":
        titolo = (request.form.get("titolo") or "").strip()
        if not titolo:
            flash("Titolo obbligatorio", "danger")
            return redirect(url_for("admin.admin_incarico_new", client_id=client.id))

        inc = Incarico(
            cliente_id=client.id,
            titolo=titolo,
            descrizione=(request.form.get("descrizione") or "").strip() or None,
            stato=(request.form.get("stato") or "Attivo").strip() or "Attivo",
        )
        db.session.add(inc)
        db.session.commit()
        ensure_calendar_for_incarico(inc)
        audit("admin_incarico_create", f"incarico_id={inc.id}", actor=current_user)
        flash("Incarico creato", "success")
        return redirect(url_for("admin.admin_incarico_detail", incarico_id=inc.id))
    return render_template("admin_incarico_new.html", client=client, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/incarichi/<int:incarico_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("240 per hour")
def admin_incarico_detail(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)
    ensure_calendar_for_incarico(inc)

    if request.method == "POST":
        inc.titolo = (request.form.get("titolo") or "").strip()
        inc.descrizione = (request.form.get("descrizione") or "").strip() or None
        inc.stato = (request.form.get("stato") or "Attivo").strip() or "Attivo"
        if not inc.titolo:
            flash("Titolo obbligatorio", "danger")
            return redirect(url_for("admin.admin_incarico_detail", incarico_id=inc.id))
        db.session.commit()
        audit("admin_incarico_update", f"incarico_id={inc.id}", actor=current_user)
        flash("Incarico aggiornato", "success")
        return redirect(url_for("admin.admin_incarico_detail", incarico_id=inc.id))

    stats = incarico_stats(inc.id)
    return render_template("admin_incarico_detail.html", incarico=inc, stats=stats, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/incarichi/<int:incarico_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per hour")
def admin_incarico_delete(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)
    client_id = inc.cliente_id
    db.session.delete(inc)
    db.session.commit()
    audit("admin_incarico_delete", f"incarico_id={incarico_id}", actor=current_user)
    flash("Incarico eliminato", "success")
    return redirect(url_for("admin.admin_client_detail", client_id=client_id))

# =========================
# Admin - Calendario Eventi + bulk (come tuo codice, con limiter)
# =========================

@admin.route("/admin/incarichi/<int:incarico_id>/calendar")
@login_required
@role_required("admin")
def admin_incarico_calendar(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)
    ensure_calendar_for_incarico(inc)

    status_filter = (request.args.get("status") or "").strip()
    docente_filter = (request.args.get("docente_id") or "").strip()

    docenti = Docente.query.order_by(Docente.cognome.asc(), Docente.nome.asc()).all()

    eventi_query = Evento.query.filter_by(incarico_id=inc.id)
    if status_filter in ("Opzionato", "Confermato"):
        eventi_query = eventi_query.filter(Evento.status == status_filter)
    if docente_filter.isdigit():
        did = int(docente_filter)
        eventi_query = (
            eventi_query.join(event_docente, event_docente.c.evento_id == Evento.id)
            .filter(event_docente.c.docente_id == did)
        )

    eventi = eventi_query.order_by(Evento.start_dt.asc()).all()
    stats = incarico_stats(inc.id)

    return render_template(
        "admin_incarico_calendar.html",
        incarico=inc,
        docenti=docenti,
        eventi=eventi,
        status_filter=status_filter,
        docente_filter=docente_filter,
        stats=stats,
        app_name=current_app.config["APP_NAME"],
    )

@admin.route("/admin/incarichi/<int:incarico_id>/events.json")
@login_required
@role_required("admin")
@limiter.limit("240 per minute")
def admin_incarico_events_json(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)
    ensure_calendar_for_incarico(inc)

    status_filter = (request.args.get("status") or "").strip()
    docente_filter = (request.args.get("docente_id") or "").strip()

    q = Evento.query.filter_by(incarico_id=inc.id)
    if status_filter in ("Opzionato", "Confermato"):
        q = q.filter(Evento.status == status_filter)
    if docente_filter.isdigit():
        did = int(docente_filter)
        q = (
            q.join(event_docente, event_docente.c.evento_id == Evento.id)
            .filter(event_docente.c.docente_id == did)
        )

    eventi = q.all()
    out = []
    for e in eventi:
        out.append({
            "id": e.id,
            "title": f"{e.titolo} [{e.status}]",
            "start": e.start_dt.isoformat(),
            "end": e.end_dt.isoformat(),
        })
    return jsonify(out)

@admin.route("/admin/incarichi/<int:incarico_id>/events/new", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per minute")
def admin_event_new(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)

    titolo = (request.form.get("titolo") or "").strip()
    note = (request.form.get("note") or "").strip() or None
    status = (request.form.get("status") or "Opzionato").strip()
    exclude_weekends = (request.form.get("exclude_weekends") or "") == "on"

    if status not in ("Opzionato", "Confermato"):
        status = "Opzionato"

    if not titolo:
        flash("Titolo evento obbligatorio", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    date_start_s = request.form.get("date_start")
    date_end_s = request.form.get("date_end")
    time_start_s = request.form.get("time_start")
    time_end_s = request.form.get("time_end")

    start_dt_s = request.form.get("start_dt")
    end_dt_s = request.form.get("end_dt")

    created = 0

    try:
        if date_start_s and date_end_s and time_start_s and time_end_s:
            d_start = parse_date(date_start_s)
            d_end = parse_date(date_end_s)
            t_start = parse_time(time_start_s)
            t_end = parse_time(time_end_s)

            if d_end < d_start:
                raise ValueError("La data fine deve essere successiva o uguale alla data inizio")

            if datetime.combine(date.today(), t_end) <= datetime.combine(date.today(), t_start):
                raise ValueError("Ora fine deve essere successiva all'ora inizio")

            cur = d_start
            while cur <= d_end:
                if exclude_weekends and cur.weekday() in (5, 6):
                    cur += timedelta(days=1)
                    continue

                start_dt = datetime.combine(cur, t_start)
                end_dt = datetime.combine(cur, t_end)

                e = Evento(
                    incarico_id=inc.id,
                    titolo=titolo,
                    note=note,
                    start_dt=start_dt,
                    end_dt=end_dt,
                    status=status,
                )
                db.session.add(e)
                created += 1
                cur += timedelta(days=1)

            db.session.commit()
            audit("admin_event_create_range", f"incarico_id={inc.id} count={created}", actor=current_user)
            flash(f"Creati {created} eventi (uno al giorno nel range selezionato)", "success")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

        if start_dt_s and end_dt_s:
            start_dt = parse_dt_local(start_dt_s)
            end_dt = parse_dt_local(end_dt_s)
            if end_dt <= start_dt:
                raise ValueError("Fine evento deve essere successiva all'inizio")

            e = Evento(
                incarico_id=inc.id,
                titolo=titolo,
                note=note,
                start_dt=start_dt,
                end_dt=end_dt,
                status=status,
            )
            db.session.add(e)
            db.session.commit()
            audit("admin_event_create", f"incarico_id={inc.id} event_id={e.id}", actor=current_user)
            flash("Evento creato", "success")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

        raise ValueError("Compila data inizio/fine e ora inizio/fine")

    except ValueError as ex:
        flash(str(ex), "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

@admin.route("/admin/events/<int:event_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per minute")
def admin_event_edit(event_id):
    e = db.session.get(Evento, event_id) or abort(404)
    inc = e.incarico
    docenti = Docente.query.order_by(Docente.cognome.asc(), Docente.nome.asc()).all()

    if request.method == "POST":
        titolo = (request.form.get("titolo") or "").strip()
        note = (request.form.get("note") or "").strip() or None
        start_s = request.form.get("start_dt")
        end_s = request.form.get("end_dt")
        status = (request.form.get("status") or "Opzionato").strip()

        if status not in ("Opzionato", "Confermato"):
            status = "Opzionato"

        try:
            start_dt = parse_dt_local(start_s)
            end_dt = parse_dt_local(end_s)
        except ValueError as ex:
            flash(str(ex), "danger")
            return redirect(url_for("admin.admin_event_edit", event_id=e.id))

        if not titolo:
            flash("Titolo evento obbligatorio", "danger")
            return redirect(url_for("admin.admin_event_edit", event_id=e.id))

        if end_dt <= start_dt:
            flash("Fine evento deve essere successiva all'inizio", "danger")
            return redirect(url_for("admin.admin_event_edit", event_id=e.id))

        docente_ids = request.form.getlist("docente_ids")
        docente_ids_int: List[int] = []
        for x in docente_ids:
            try:
                docente_ids_int.append(int(x))
            except ValueError:
                pass

        conflicts = validate_docenti_no_overlap(docente_ids_int, start_dt, end_dt, exclude_event_ids=[e.id])
        if conflicts:
            flash(conflicts_to_message(conflicts), "danger")
            return redirect(url_for("admin.admin_event_edit", event_id=e.id))

        e.titolo = titolo
        e.note = note
        e.start_dt = start_dt
        e.end_dt = end_dt
        e.status = status

        new_docenti = Docente.query.filter(Docente.id.in_(docente_ids_int)).all() if docente_ids_int else []
        e.docenti = new_docenti

        db.session.commit()
        audit("admin_event_update", f"event_id={e.id}", actor=current_user)
        flash("Evento aggiornato", "success")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    return render_template("admin_event_edit.html", evento=e, incarico=inc, docenti=docenti, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/events/<int:event_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per hour")
def admin_event_delete(event_id):
    e = db.session.get(Evento, event_id) or abort(404)
    incarico_id = e.incarico_id
    db.session.delete(e)
    db.session.commit()
    audit("admin_event_delete", f"event_id={event_id}", actor=current_user)
    flash("Evento eliminato", "success")
    return redirect(url_for("admin.admin_incarico_calendar", incarico_id=incarico_id))

@admin.route("/admin/incarichi/<int:incarico_id>/assign", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("30 per minute")
def admin_bulk_assign(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)
    event_ids = request.form.getlist("event_ids")
    docente_ids = request.form.getlist("docente_ids_assign")

    try:
        event_ids_int = [int(x) for x in event_ids]
        docente_ids_int = [int(x) for x in docente_ids]
    except ValueError:
        flash("Selezione non valida", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if not event_ids_int:
        flash("Seleziona almeno un evento", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if not docente_ids_int:
        flash("Seleziona almeno un docente", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    events = Evento.query.filter(Evento.id.in_(event_ids_int), Evento.incarico_id == inc.id).all()
    docenti = Docente.query.filter(Docente.id.in_(docente_ids_int)).all()

    if not events:
        flash("Nessun evento valido selezionato", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if not docenti:
        flash("Nessun docente valido selezionato", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    all_conflicts: Dict[int, List[Evento]] = {}
    for ev in events:
        conflicts = validate_docenti_no_overlap(docente_ids_int, ev.start_dt, ev.end_dt, exclude_event_ids=[ev.id])
        if conflicts:
            for did, evs in conflicts.items():
                all_conflicts.setdefault(did, [])
                all_conflicts[did].extend(evs)

    if all_conflicts:
        flash(conflicts_to_message(all_conflicts), "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    for ev in events:
        current_ids = {d.id for d in ev.docenti}
        for d in docenti:
            if d.id not in current_ids:
                ev.docenti.append(d)

    db.session.commit()
    audit("admin_bulk_assign", f"incarico_id={inc.id} events={len(events)} docenti={len(docenti)}", actor=current_user)
    flash("Assegnazione completata", "success")
    return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

@admin.route("/admin/incarichi/<int:incarico_id>/bulk-update", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("20 per minute")
def admin_bulk_update_events(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)

    event_ids = request.form.getlist("event_ids")
    try:
        event_ids_int = [int(x) for x in event_ids]
    except ValueError:
        flash("Selezione eventi non valida", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if not event_ids_int:
        flash("Seleziona almeno un evento", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    events = Evento.query.filter(Evento.id.in_(event_ids_int), Evento.incarico_id == inc.id).order_by(Evento.start_dt.asc()).all()
    if not events:
        flash("Nessun evento valido selezionato", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    apply_title = (request.form.get("apply_title") == "on")
    new_title = (request.form.get("bulk_title") or "")
    apply_notes = (request.form.get("apply_notes") == "on")
    new_notes_raw = (request.form.get("bulk_notes") or "")
    new_notes = new_notes_raw.strip() or None

    apply_docenti = (request.form.get("apply_docenti") == "on")
    docente_ids_update = request.form.getlist("docente_ids_update")
    docente_ids_update_int: List[int] = []
    for x in docente_ids_update:
        try:
            docente_ids_update_int.append(int(x))
        except ValueError:
            pass
    new_docenti = Docente.query.filter(Docente.id.in_(docente_ids_update_int)).all() if docente_ids_update_int else []

    shift_days = parse_int_or_none(request.form.get("shift_days") or "") or 0
    shift_minutes = parse_int_or_none(request.form.get("shift_minutes") or "") or 0

    apply_time_only = (request.form.get("apply_time_only") == "on")
    time_start_s = (request.form.get("bulk_time_start") or "").strip()
    time_end_s = (request.form.get("bulk_time_end") or "").strip()

    apply_absolute = (request.form.get("apply_absolute") == "on")
    abs_start_s = (request.form.get("bulk_abs_start") or "").strip()
    abs_end_s = (request.form.get("bulk_abs_end") or "").strip()

    try:
        bulk_time_start = parse_time(time_start_s) if (apply_time_only and time_start_s) else None
        bulk_time_end = parse_time(time_end_s) if (apply_time_only and time_end_s) else None
        abs_start = parse_dt_local(abs_start_s) if (apply_absolute and abs_start_s) else None
        abs_end = parse_dt_local(abs_end_s) if (apply_absolute and abs_end_s) else None
    except ValueError as ex:
        flash(str(ex), "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if apply_time_only:
        if bulk_time_start is None or bulk_time_end is None:
            flash("Per la modifica solo ORARIO devi compilare sia Ora inizio che Ora fine.", "danger")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))
        if datetime.combine(date.today(), bulk_time_end) <= datetime.combine(date.today(), bulk_time_start):
            flash("Ora fine deve essere successiva all'ora inizio (bulk).", "danger")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if apply_absolute:
        if abs_start is None or abs_end is None:
            flash("Per la modifica ASSOLUTA devi compilare sia Start assoluto che End assoluto.", "danger")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))
        if abs_end <= abs_start:
            flash("End assoluto deve essere successivo a Start assoluto.", "danger")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    planned: List[Tuple[int, datetime, datetime, List[int]]] = []
    selected_ids_set = set(event_ids_int)

    for ev in events:
        ns = ev.start_dt
        ne = ev.end_dt

        if shift_days or shift_minutes:
            delta = timedelta(days=shift_days, minutes=shift_minutes)
            ns = ns + delta
            ne = ne + delta

        if apply_time_only:
            ns = datetime.combine(ns.date(), bulk_time_start)
            ne = datetime.combine(ne.date(), bulk_time_end)

        if apply_absolute:
            ns = abs_start
            ne = abs_end

        if ne <= ns:
            flash(f"Evento ID {ev.id}: fine non valida (deve essere successiva all'inizio).", "danger")
            return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

        if apply_docenti:
            dids = docente_ids_update_int[:]
        else:
            dids = [d.id for d in ev.docenti]

        planned.append((ev.id, ns, ne, dids))

    all_conflicts: Dict[int, List[Evento]] = {}
    exclude_event_ids = list(selected_ids_set)

    docenti_to_check: Set[int] = set()
    for _, _, _, dids in planned:
        for did in dids:
            docenti_to_check.add(did)

    for _, ns, ne, dids in planned:
        for did in dids:
            conf = docente_has_conflict(did, ns, ne, exclude_event_ids=exclude_event_ids)
            if conf:
                all_conflicts.setdefault(did, [])
                all_conflicts[did].extend(conf)

    if all_conflicts:
        flash(conflicts_to_message(all_conflicts), "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    internal_parts = []
    for did in docenti_to_check:
        items = [(eid, s, e) for (eid, s, e, dids) in planned if did in dids]
        if len(items) < 2:
            continue
        items.sort(key=lambda x: x[1])
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                a_id, a_s, a_e = items[i]
                b_id, b_s, b_e = items[j]
                if intervals_overlap(a_s, a_e, b_s, b_e):
                    d = db.session.get(Docente, did)
                    dname = d.display_name if d else f"Docente {did}"
                    internal_parts.append(
                        f"- {dname}: overlap tra eventi selezionati ID {a_id} e ID {b_id} ({a_s.strftime('%Y-%m-%d %H:%M')} - {a_e.strftime('%Y-%m-%d %H:%M')})"
                    )

    if internal_parts:
        msg = "Vincolo docenti: modifica bulk impossibile per sovrapposizione tra eventi selezionati.\n" + "\n".join(internal_parts[:25])
        if len(internal_parts) > 25:
            msg += f"\n... (+{len(internal_parts)-25} altri)"
        flash(msg, "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    planned_map = {eid: (s, e, dids) for (eid, s, e, dids) in planned}

    for ev in events:
        ns, ne, dids = planned_map[ev.id]

        if apply_title:
            ev.titolo = (new_title or "").strip()

        if apply_notes:
            ev.note = new_notes

        if shift_days or shift_minutes or apply_time_only or apply_absolute:
            ev.start_dt = ns
            ev.end_dt = ne

        if apply_docenti:
            ev.docenti = new_docenti

    db.session.commit()
    audit("admin_bulk_update", f"incarico_id={inc.id} events={len(events)}", actor=current_user)
    flash(f"Bulk update completato su {len(events)} eventi.", "success")
    return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

@admin.route("/admin/incarichi/<int:incarico_id>/bulk-delete", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("20 per minute")
def admin_bulk_delete_events(incarico_id):
    inc = db.session.get(Incarico, incarico_id) or abort(404)

    event_ids = request.form.getlist("event_ids")
    try:
        event_ids_int = [int(x) for x in event_ids]
    except ValueError:
        flash("Selezione eventi non valida", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    if not event_ids_int:
        flash("Seleziona almeno un evento", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    events = Evento.query.filter(Evento.id.in_(event_ids_int), Evento.incarico_id == inc.id).all()
    if not events:
        flash("Nessun evento valido selezionato", "danger")
        return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

    for ev in events:
        db.session.delete(ev)

    db.session.commit()
    audit("admin_bulk_delete", f"incarico_id={inc.id} events={len(events)}", actor=current_user)
    flash(f"Eliminati {len(events)} eventi.", "success")
    return redirect(url_for("admin.admin_incarico_calendar", incarico_id=inc.id))

# =========================
# Admin - Docenti + CV
# =========================

@admin.route("/admin/docenti")
@login_required
@role_required("admin")
def admin_docenti():
    q = (request.args.get("q") or "").strip()
    query = Docente.query
    if q:
        query = query.filter(
            (Docente.nome.ilike(f"%{q}%")) |
            (Docente.cognome.ilike(f"%{q}%")) |
            (Docente.email.ilike(f"%{q}%")) |
            (Docente.codice_fiscale.ilike(f"%{q}%")) |
            (Docente.ragione_sociale.ilike(f"%{q}%"))
        )
    docenti = query.order_by(Docente.cognome.asc(), Docente.nome.asc()).all()
    return render_template("admin_docenti.html", docenti=docenti, q=q, app_name=current_app.config["APP_NAME"])

@admin.route("/admin/docenti/<int:docente_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
@limiter.limit("120 per hour")
def admin_docente_detail(docente_id: int):
    d = db.session.get(Docente, docente_id) or abort(404)
    u = d.user

    if request.method == "POST":
        d.nome = (request.form.get("nome") or "").strip()
        d.cognome = (request.form.get("cognome") or "").strip()
        d.email = (request.form.get("email") or "").strip() or None
        d.sesso = (request.form.get("sesso") or "").strip() or None
        d.codice_fiscale = (request.form.get("codice_fiscale") or "").strip() or None
        d.tipo_soggetto = (request.form.get("tipo_soggetto") or "Libero Professionista").strip()
        if d.tipo_soggetto not in ("Azienda", "Libero Professionista"):
            d.tipo_soggetto = "Libero Professionista"
        d.ragione_sociale = (request.form.get("ragione_sociale") or "").strip() or None
        d.regime_iva = (request.form.get("regime_iva") or "").strip() or None
        d.banca_appoggio = (request.form.get("banca_appoggio") or "").strip() or None
        d.intestatario_banca = (request.form.get("intestatario_banca") or "").strip() or None
        d.iban = (request.form.get("iban") or "").strip() or None
        d.bic_swift = (request.form.get("bic_swift") or "").strip() or None

        d.regime_iva = (request.form.get("regime_iva") or "").strip() or None
        if d.regime_iva and d.regime_iva not in REGIME_IVA_CHOICES:
            flash("Regime IVA / Tipo P.IVA non valido.", "danger")
            return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

        d.partita_iva = (request.form.get("partita_iva") or "").strip() or None
        piva_err = validate_piva(d.partita_iva or "")
        if piva_err:
            flash(piva_err, "danger")
            return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

        if not d.nome or not d.cognome:
            flash("Nome e Cognome sono obbligatori", "danger")
            return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

        if u:
            new_status = (request.form.get("user_status") or u.status).strip()
            if new_status not in ("pending", "active", "disabled"):
                new_status = u.status
            u.status = new_status

            new_pwd = (request.form.get("new_password") or "").strip()
            if new_pwd:
                msg = validate_password_policy(new_pwd)
                if msg:
                    flash(msg, "danger")
                    return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))
                u.set_password(new_pwd)

        cv_file = request.files.get("cv_pdf")
        if cv_file and cv_file.filename:
            try:
                cv_name = save_cv_pdf(cv_file, docente_id=d.id)
                # cleanup vecchio file se esiste
                if d.cv_filename and d.cv_filename != cv_name:
                    # non cancelliamo qui per semplicità: in produzione puoi implementare cleanup sicuro
                    pass
                d.cv_filename = cv_name
                d.cv_uploaded_at = datetime.utcnow()
            except ValueError as ex:
                flash(str(ex), "danger")
                return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

        db.session.commit()
        audit("admin_docente_update", f"docente_id={d.id}", actor=current_user)
        flash("Docente aggiornato", "success")
        return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

    return render_template("admin_docente_detail.html", app_name=current_app.config["APP_NAME"], docente=d, user=u)

@admin.route("/admin/docenti/<int:docente_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("60 per hour")
def admin_docenti_delete(docente_id):
    d = db.session.get(Docente, docente_id) or abort(404)
    db.session.delete(d)
    db.session.commit()
    audit("admin_docente_delete", f"docente_id={docente_id}", actor=current_user)
    flash("Docente eliminato", "success")
    return redirect(url_for("admin.admin_docenti"))

@admin.route("/admin/docenti/<int:docente_id>/cv")
@login_required
@role_required("admin")
@limiter.limit("120 per hour")
def admin_docente_cv(docente_id: int):
    d = db.session.get(Docente, docente_id) or abort(404)
    if not d.cv_filename:
        flash("CV non disponibile", "danger")
        return redirect(url_for("admin.admin_docente_detail", docente_id=d.id))

    download = (request.args.get("download", "1") or "1").strip() != "0"
    audit("admin_docente_cv_access", f"docente_id={d.id} download={download}", actor=current_user)
    return send_docente_cv_file(d, download=download)

# =========================
# Docente - Dashboard (anti-IDOR: check ownership)
# =========================

@docente_bp.route("/docente")
@login_required
@role_required("docente")
def docente_dashboard():
    docente = current_user.docente
    if docente is None:
        abort(403)

    incarichi = (
        Incarico.query
        .join(Evento, Evento.incarico_id == Incarico.id)
        .join(event_docente, event_docente.c.evento_id == Evento.id)
        .filter(event_docente.c.docente_id == docente.id)
        .distinct()
        .order_by(Incarico.id.desc())
        .all()
    )

    return render_template(
        "docente_dashboard.html",
        docente=docente,
        incarichi=incarichi,
        app_name=current_app.config["APP_NAME"]
    )

@docente_bp.route("/docente/events.json")
@login_required
@role_required("docente")
@limiter.limit("240 per minute")
def docente_events_json():
    docente = current_user.docente
    if docente is None:
        abort(403)

    eventi = (
        Evento.query
        .join(event_docente, event_docente.c.evento_id == Evento.id)
        .filter(event_docente.c.docente_id == docente.id)
        .all()
    )

    out = []
    for e in eventi:
        out.append({
            "id": e.id,
            "title": f"{e.titolo} [{e.status}]",
            "start": e.start_dt.isoformat(),
            "end": e.end_dt.isoformat(),
            "extendedProps": {
                "incarico_id": e.incarico_id,
                "incarico_titolo": e.incarico.titolo
            }
        })
    return jsonify(out)

@docente_bp.route("/docente/incarichi/<int:incarico_id>")
@login_required
@role_required("docente")
def docente_incarico_detail(incarico_id):
    docente = current_user.docente
    if docente is None:
        abort(403)

    inc = db.session.get(Incarico, incarico_id) or abort(404)

    # Anti-IDOR: controllo ownership
    require_docente_owns_incarico(docente.id, inc.id)

    eventi = (
        Evento.query
        .join(event_docente, event_docente.c.evento_id == Evento.id)
        .filter(Evento.incarico_id == inc.id, event_docente.c.docente_id == docente.id)
        .order_by(Evento.start_dt.asc())
        .all()
    )

    return render_template(
        "docente_incarico_detail.html",
        docente=docente,
        incarico=inc,
        eventi=eventi,
        app_name=current_app.config["APP_NAME"]
    )
