import uuid
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db


event_docente = db.Table(
    "event_docente",
    db.Column("evento_id", db.Integer, db.ForeignKey("evento.id"), primary_key=True),
    db.Column("docente_id", db.Integer, db.ForeignKey("docente.id"), primary_key=True),
)


class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    code = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at


class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ragione_sociale = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=True)
    telefono = db.Column(db.String(50), nullable=True)
    note = db.Column(db.Text, nullable=True)

    incarichi = db.relationship("Incarico", backref="cliente", cascade="all, delete-orphan")


class Incarico(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey("cliente.id"), nullable=False)

    titolo = db.Column(db.String(200), nullable=False)
    descrizione = db.Column(db.Text, nullable=True)
    stato = db.Column(db.String(50), nullable=False, default="Attivo")

    calendario = db.relationship("Calendario", backref="incarico", uselist=False, cascade="all, delete-orphan")
    eventi = db.relationship("Evento", backref="incarico", cascade="all, delete-orphan")


class Calendario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incarico_id = db.Column(db.Integer, db.ForeignKey("incarico.id"), nullable=False, unique=True)
    timezone = db.Column(db.String(64), nullable=False, default="Europe/Rome")


class Evento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incarico_id = db.Column(db.Integer, db.ForeignKey("incarico.id"), nullable=False)

    titolo = db.Column(db.String(200), nullable=False)
    note = db.Column(db.Text, nullable=True)

    start_dt = db.Column(db.DateTime, nullable=False)
    end_dt = db.Column(db.DateTime, nullable=False)

    status = db.Column(db.String(20), nullable=False, default="Opzionato")  # Opzionato / Confermato
    docenti = db.relationship("Docente", secondary=event_docente, back_populates="eventi")


class Docente(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nome = db.Column(db.String(120), nullable=False)
    cognome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), nullable=True)
    data_nascita = db.Column(db.Date, nullable=True)
    luogo_nascita = db.Column(db.String(200), nullable=True)

    res_via = db.Column(db.String(200), nullable=True)
    res_civico = db.Column(db.String(30), nullable=True)
    res_comune = db.Column(db.String(120), nullable=True)
    res_cap = db.Column(db.String(10), nullable=True)
    res_provincia = db.Column(db.String(10), nullable=True)
    res_nazione = db.Column(db.String(80), nullable=True)

    sesso = db.Column(db.String(20), nullable=True)
    codice_fiscale = db.Column(db.String(32), nullable=True)
    partita_iva = db.Column(db.String(32), nullable=True)

    tipo_soggetto = db.Column(db.String(40), nullable=False, default="Libero Professionista")
    ragione_sociale = db.Column(db.String(200), nullable=True)

    regime_iva = db.Column(db.String(120), nullable=True)
    banca_appoggio = db.Column(db.String(200), nullable=True)
    intestatario_banca = db.Column(db.String(200), nullable=True)
    iban = db.Column(db.String(64), nullable=True)
    bic_swift = db.Column(db.String(64), nullable=True)

    cv_filename = db.Column(db.String(255), nullable=True)
    cv_uploaded_at = db.Column(db.DateTime, nullable=True)

    eventi = db.relationship("Evento", secondary=event_docente, back_populates="docenti")
    user = db.relationship("User", backref="docente", uselist=False, cascade="all, delete-orphan")

    @property
    def display_name(self) -> str:
        return f"{self.nome} {self.cognome}".strip()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False)  # admin | docente
    status = db.Column(db.String(20), nullable=False, default="active")  # active|pending|disabled

    docente_id = db.Column(db.Integer, db.ForeignKey("docente.id"), nullable=True)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    last_failed_login_at = db.Column(db.DateTime, nullable=True)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

    @property
    def is_active_account(self) -> bool:
        return self.status == "active"


def seed_demo_data():
    from datetime import datetime as _dt
    from .security import ensure_calendar_for_incarico
    from .security import generate_invite_code

    # Seed idempotente: se admin esiste, non rifare
    if User.query.filter_by(username="admin").first():
        return

    admin = User(username="admin", role="admin", status="active")
    admin.set_password("admin")
    db.session.add(admin)

    d1 = Docente(
        nome="Docente",
        cognome="Uno",
        email="docente1@example.com",
        tipo_soggetto="Libero Professionista",
    )
    db.session.add(d1)
    db.session.commit()

    u1 = User(username="docente1", role="docente", docente_id=d1.id, status="active")
    u1.set_password("docente1")
    db.session.add(u1)

    c = Cliente(ragione_sociale="Cliente Demo S.r.l.", email="info@clientedemo.it", telefono="0810000000")
    db.session.add(c)
    db.session.commit()

    inc = Incarico(cliente_id=c.id, titolo="Incarico Demo - Corso Cybersecurity", descrizione="Esempio incarico")
    db.session.add(inc)
    db.session.commit()

    ensure_calendar_for_incarico(inc)

    e1 = Evento(
        incarico_id=inc.id,
        titolo="Lezione 1 - Introduzione",
        note="Note demo evento 1",
        start_dt=_dt(2026, 1, 6, 9, 0),
        end_dt=_dt(2026, 1, 6, 11, 0),
        status="Confermato",
    )
    e2 = Evento(
        incarico_id=inc.id,
        titolo="Lezione 2 - Reti e Sicurezza",
        note=None,
        start_dt=_dt(2026, 1, 7, 9, 0),
        end_dt=_dt(2026, 1, 7, 11, 0),
        status="Opzionato",
    )
    e1.docenti.append(d1)
    db.session.add_all([e1, e2])

    inv = Invite(token=uuid.uuid4().hex, code=generate_invite_code())
    db.session.add(inv)

    db.session.commit()
