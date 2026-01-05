



TEMPLATES = {
    "base.html": r"""
<!doctype html>
<html lang="it">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ app_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-top: 70px; }
      .fc { max-width: 1100px; margin: 0 auto; }
      .muted { color: #6c757d; white-space: pre-line; }
      .small-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 0.9rem; }
      .stat-card { min-height: 84px; }
      code.kv { background: #f8f9fa; padding: 2px 6px; border-radius: 6px; }
      .sticky-actions { position: sticky; top: 80px; }
    </style>
    {% block head %}{% endblock %}
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('index') }}">{{ app_name }}</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navMain">
          <ul class="navbar-nav me-auto mb-2 mb-lg-0">
            {% if current_user.is_authenticated and current_user.role == 'admin' and current_user.status=='active' %}
              <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_clients') }}">Clienti</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_docenti') }}">Docenti</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_inviti') }}">Inviti</a></li>
            {% elif current_user.is_authenticated and current_user.role == 'docente' and current_user.status=='active' %}
              <li class="nav-item"><a class="nav-link" href="{{ url_for('docente_dashboard') }}">Dashboard</a></li>
            {% endif %}
          </ul>
          <ul class="navbar-nav ms-auto">
            {% if current_user.is_authenticated %}
              <li class="nav-item">
                <span class="navbar-text me-3">
                  Utente: <span class="small-mono">{{ current_user.username }}</span> ({{ current_user.role }}) - <span class="small-mono">{{ current_user.status }}</span>
                </span>
              </li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('account_change_password') }}">Cambia password</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>

    <main class="container">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for cat, msg in messages %}
            <div class="alert alert-{{ cat }} alert-dismissible fade show" role="alert">
              {{ msg }}
              <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      {% block content %}{% endblock %}
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
  </body>
</html>
""",
    "login.html": r"""
<!doctype html>
<html lang="it">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - {{ app_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-md-5">
          <div class="card shadow-sm">
            <div class="card-body">
              <h4 class="mb-3">Login</h4>
              {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                  {% for cat, msg in messages %}
                    <div class="alert alert-{{ cat }}">{{ msg }}</div>
                  {% endfor %}
                {% endif %}
              {% endwith %}
              <form method="post">
                <div class="mb-3">
                  <label class="form-label">Username</label>
                  <input class="form-control" name="username" autocomplete="username" required>
                </div>
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input class="form-control" type="password" name="password" autocomplete="current-password" required>
                </div>
                <button class="btn btn-primary w-100" type="submit">Accedi</button>
              </form>
              <hr>
              <div class="small text-muted">
                Demo: admin/admin oppure docente1/docente1
              </div>
            </div>
          </div>
          <div class="text-center mt-3 text-muted small">
            {{ app_name }}
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
""",
    "account_password.html": r"""
{% extends "base.html" %}
{% block content %}
  <h2 class="mb-3">Cambia Password</h2>
  <div class="card">
    <div class="card-body">
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Password attuale</label>
          <input class="form-control" type="password" name="current_password" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Nuova password</label>
          <input class="form-control" type="password" name="new_password" required>
          <div class="small muted mt-1">Minimo 8 caratteri.</div>
        </div>
        <div class="mb-3">
          <label class="form-label">Ripeti nuova password</label>
          <input class="form-control" type="password" name="new_password2" required>
        </div>
        <button class="btn btn-primary" type="submit">Aggiorna</button>
      </form>
    </div>
  </div>
{% endblock %}
""",
    "invite_register.html": r"""
<!-- --- TEMPLATE: sostituisci INTERAMENTE invite_register.html con questo blocco --- -->
<!doctype html>
<html lang="it">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Registrazione Docente - {{ app_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-top: 26px; }
      .section-title { font-size: 1.05rem; font-weight: 600; }
      .section-sub { color: #6c757d; font-size: .92rem; }
      .card { border: 0; }
      .card.shadow-soft { box-shadow: 0 .25rem .9rem rgba(0,0,0,.06); }
      .req::after { content: " *"; color: #dc3545; font-weight: 700; }
      .help { color: #6c757d; font-size: .9rem; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    </style>
  </head>
  <body class="bg-light">
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-12 col-lg-10 col-xl-9">
          <div class="card shadow-soft">
            <div class="card-body p-4 p-lg-5">
              <div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
                <div>
                  <h3 class="mb-1">Registrazione Docente</h3>
                  <div class="text-muted">
                    Invito monouso. Dopo la registrazione l'account sarà in stato <b>pending</b> e verrà sbloccato dall'amministratore.
                  </div>
                </div>
              </div>

              {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                  {% for cat, msg in messages %}
                    <div class="alert alert-{{ cat }} mb-3">{{ msg }}</div>
                  {% endfor %}
                {% endif %}
              {% endwith %}

              <form method="post" enctype="multipart/form-data" novalidate>
                <!-- SEZIONE: Accesso -->
                <div class="mb-3">
                  <div class="section-title">Dati accesso</div>
                  <div class="section-sub">Il codice invito è obbligatorio. Username verrà generato automaticamente da Nome e Cognome.</div>
                </div>

                <div class="row g-3">
                  <div class="col-md-4">
                    <label class="form-label req">Codice invito</label>
                    <input class="form-control" name="invite_code" required>
                  </div>

                  <div class="col-md-8">
                    <label class="form-label">Email</label>
                    <input class="form-control" name="email" type="email" autocomplete="email" placeholder="es. nome.cognome@example.com">
                  </div>

                  <div class="col-md-6">
                    <label class="form-label req">Password</label>
                    <input class="form-control" name="password" type="password" autocomplete="new-password" required>
                    <div class="help mt-1">Minimo 8 caratteri. Deve rispettare la policy lato server.</div>
                  </div>

                  <div class="col-md-6">
                    <label class="form-label req">Ripeti password</label>
                    <input class="form-control" name="password2" type="password" autocomplete="new-password" required>
                  </div>
                </div>

                <hr class="my-4">

                <!-- SEZIONE: Inquadramento fiscale -->
                <div class="mb-3">
                  <div class="section-title">Inquadramento</div>
                  <div class="section-sub">Seleziona il regime IVA e indica la Partita IVA quando richiesta.</div>
                </div>

                <div class="row g-3">
                  <div class="col-md-4">
                    <label class="form-label req">Tipo registrazione</label>
                    <select class="form-select" name="tipo_soggetto" id="tipoSoggetto" required>
                      <option value="Libero Professionista" selected>Libero Professionista</option>
                      <option value="Azienda">Azienda</option>
                    </select>
                  </div>

                  <div class="col-md-8">
                    <label class="form-label req">Regime IVA / Tipo P.IVA</label>
                    <select class="form-select" name="regime_iva" id="regimeIva" required>
                      <option value="" selected disabled>Seleziona...</option>
                      {% for opt in regime_iva_choices %}
                        <option value="{{ opt }}">{{ opt }}</option>
                      {% endfor %}
                    </select>
                  </div>

                  <div class="col-md-6">
                    <label class="form-label" id="lblPiva">Partita IVA</label>
                    <input class="form-control" name="partita_iva" id="partitaIva" inputmode="numeric" maxlength="11" placeholder="11 cifre">
                    <div class="help mt-1" id="pivaHelp"></div>
                  </div>

                  <div class="col-md-6">
                    <label class="form-label" id="lblRagSoc">Ragione sociale</label>
                    <input class="form-control" name="ragione_sociale" id="ragioneSociale" placeholder="Obbligatoria se Azienda">
                  </div>
                </div>

                <hr class="my-4">

                <!-- SEZIONE: Anagrafica -->
                <div class="mb-3">
                  <div class="section-title">Anagrafica</div>
                  <div class="section-sub">Nome, Cognome, Data e Luogo di nascita sono obbligatori.</div>
                </div>

                <div class="row g-3">
                  <div class="col-md-4">
                    <label class="form-label req">Nome</label>
                    <input class="form-control" name="nome" id="nome" required>
                  </div>

                  <div class="col-md-4">
                    <label class="form-label req">Cognome</label>
                    <input class="form-control" name="cognome" id="cognome" required>
                  </div>

                  <div class="col-md-4">
                    <label class="form-label">Sesso</label>
                    <select class="form-select" name="sesso">
                      <option value="" selected>—</option>
                      <option value="M">M</option>
                      <option value="F">F</option>
                      <option value="Altro">Altro</option>
                    </select>
                  </div>

                  <div class="col-md-4">
                    <label class="form-label req">Data di nascita</label>
                    <input class="form-control" type="date" name="data_nascita" required>
                  </div>

                  <div class="col-md-5">
                    <label class="form-label req">Comune di nascita</label>
                    <input class="form-control" name="luogo_nascita_comune" id="birthComune" list="dlBirthComuni" autocomplete="off" required>
                    <datalist id="dlBirthComuni"></datalist>
                    <div class="help mt-1">Digita almeno 2 caratteri per ottenere suggerimenti.</div>
                  </div>

                  <div class="col-md-3">
                    <label class="form-label req">Provincia di nascita</label>
                    <input class="form-control mono" name="luogo_nascita_provincia" id="birthProv" list="dlProvince" maxlength="2" placeholder="Es. NA" required>
                  </div>

                  <div class="col-md-6">
                    <label class="form-label">Codice Fiscale</label>
                    <input class="form-control" name="codice_fiscale" placeholder="Opzionale">
                  </div>
                </div>

                <hr class="my-4">

                <!-- SEZIONE: Residenza -->
                <div class="mb-3">
                  <div class="section-title">Residenza</div>
                  <div class="section-sub">Via, Civico, Comune, CAP e Provincia sono obbligatori.</div>
                </div>

                <div class="row g-3">
                  <div class="col-md-6">
                    <label class="form-label req">Via</label>
                    <input class="form-control" name="res_via" required>
                  </div>

                  <div class="col-md-2">
                    <label class="form-label req">Civico</label>
                    <input class="form-control" name="res_civico" required>
                  </div>

                  <div class="col-md-4">
                    <label class="form-label req">CAP</label>
                    <input class="form-control mono" name="res_cap" inputmode="numeric" pattern="[0-9]{5}" maxlength="5" placeholder="5 cifre" required>
                  </div>

                  <div class="col-md-6">
                    <label class="form-label req">Comune</label>
                    <input class="form-control" name="res_comune" id="resComune" list="dlResComuni" autocomplete="off" required>
                    <datalist id="dlResComuni"></datalist>
                    <div class="help mt-1">Digita almeno 2 caratteri per ottenere suggerimenti.</div>
                  </div>

                  <div class="col-md-3">
                    <label class="form-label req">Provincia</label>
                    <input class="form-control mono" name="res_provincia" id="resProv" list="dlProvince" maxlength="2" placeholder="Es. NA" required>
                  </div>

                  <div class="col-md-3">
                    <label class="form-label">Nazione</label>
                    <input class="form-control" name="res_nazione" value="Italia">
                  </div>
                </div>

                <hr class="my-4">

                <!-- SEZIONE: Coordinate bancarie -->
                <div class="mb-3">
                  <div class="section-title">Dati bancari (opzionali)</div>
                  <div class="section-sub">Compila solo se necessario per pagamenti.</div>
                </div>

                <div class="row g-3">
                  <div class="col-md-6">
                    <label class="form-label">Banca di appoggio</label>
                    <input class="form-control" name="banca_appoggio">
                  </div>

                  <div class="col-md-6">
                    <label class="form-label">Intestatario banca</label>
                    <input class="form-control" name="intestatario_banca">
                  </div>

                  <div class="col-md-6">
                    <label class="form-label">IBAN</label>
                    <input class="form-control mono" name="iban" placeholder="IT00X0000000000000000000000">
                  </div>

                  <div class="col-md-6">
                    <label class="form-label">BIC/SWIFT</label>
                    <input class="form-control mono" name="bic_swift" placeholder="XXXXXXXXXXX">
                  </div>
                </div>

                <hr class="my-4">

                <!-- SEZIONE: CV -->
                <div class="mb-3">
                  <div class="section-title">Curriculum</div>
                  <div class="section-sub">Carica un PDF (obbligatorio).</div>
                </div>

                <div class="row g-3">
                  <div class="col-12">
                    <label class="form-label req">CV (PDF)</label>
                    <input class="form-control" type="file" name="cv_pdf" accept="application/pdf" required>
                    <div class="help mt-1">Solo PDF. Max {{ max_cv_mb }} MB.</div>
                  </div>
                </div>

                <div class="mt-4 d-flex flex-wrap gap-2">
                  <button class="btn btn-success px-4" type="submit">Completa registrazione</button>
                  <a class="btn btn-outline-secondary" href="{{ url_for('login') }}">Torna al login</a>
                </div>
              </form>
            </div>
          </div>

          <div class="text-center mt-3 text-muted small">
            {{ app_name }}
          </div>
        </div>
      </div>
    </div>

    <datalist id="dlProvince"></datalist>

    <script>
      (function () {
        const regimeIva = document.getElementById('regimeIva');
        const piva = document.getElementById('partitaIva');
        const lblPiva = document.getElementById('lblPiva');
        const pivaHelp = document.getElementById('pivaHelp');

        const tipoSoggetto = document.getElementById('tipoSoggetto');
        const ragSoc = document.getElementById('ragioneSociale');
        const lblRagSoc = document.getElementById('lblRagSoc');

        const dlProvince = document.getElementById('dlProvince');

        const birthComune = document.getElementById('birthComune');
        const birthProv = document.getElementById('birthProv');
        const dlBirthComuni = document.getElementById('dlBirthComuni');

        const resComune = document.getElementById('resComune');
        const resProv = document.getElementById('resProv');
        const dlResComuni = document.getElementById('dlResComuni');

        function setRequired(el, required) {
          if (!el) return;
          if (required) el.setAttribute('required', 'required');
          else el.removeAttribute('required');
        }

        function setReqLabel(labelEl, required) {
          if (!labelEl) return;
          if (required) labelEl.classList.add('req');
          else labelEl.classList.remove('req');
        }

        function normalizeProv(v) {
          return (v || '').trim().toUpperCase().slice(0, 2);
        }

        function applyFiscalRules() {
          const regime = (regimeIva?.value || '').trim();
          const isRASecca = (regime === 'R.A. secca');

          // P.IVA obbligatoria salvo R.A. secca
          setRequired(piva, !isRASecca);
          setReqLabel(lblPiva, !isRASecca);
          pivaHelp.textContent = isRASecca
            ? "Opzionale per R.A. secca."
            : "Obbligatoria per il regime selezionato (11 cifre).";

          // Ragione sociale obbligatoria se Azienda
          const isAzienda = (tipoSoggetto?.value === 'Azienda');
          setRequired(ragSoc, isAzienda);
          setReqLabel(lblRagSoc, isAzienda);
        }

        async function fetchJson(url) {
          const r = await fetch(url, { headers: { 'Accept': 'application/json' }});
          if (!r.ok) return null;
          return await r.json();
        }

        async function loadProvinceDatalist() {
          const data = await fetchJson('/api/italy/province');
          if (!data || !Array.isArray(data)) return;

          dlProvince.innerHTML = '';
          for (const p of data) {
            const opt = document.createElement('option');
            opt.value = (p.code || '').toUpperCase();
            opt.label = (p.name || '').trim();
            dlProvince.appendChild(opt);
          }
        }

        function debounce(fn, wait) {
          let t = null;
          return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), wait);
          };
        }

        async function updateComuniDatalist(q, prov, dlEl) {
          if (!dlEl) return;
          const qq = (q || '').trim();
          const pv = normalizeProv(prov);

          if (qq.length < 2) {
            dlEl.innerHTML = '';
            return;
          }

          const url = new URL('/api/italy/comuni', window.location.origin);
          url.searchParams.set('q', qq);
          url.searchParams.set('limit', '25');
          if (pv) url.searchParams.set('prov', pv);

          const data = await fetchJson(url.toString());
          if (!data || !Array.isArray(data)) {
            dlEl.innerHTML = '';
            return;
          }

          dlEl.innerHTML = '';
          for (const c of data) {
            const opt = document.createElement('option');
            opt.value = c.name;       // valore inserito nel campo (Comune)
            opt.label = `${c.name} (${c.prov})`;
            dlEl.appendChild(opt);
          }
        }

        const debouncedBirthComuni = debounce(() => updateComuniDatalist(birthComune.value, birthProv.value, dlBirthComuni), 180);
        const debouncedResComuni = debounce(() => updateComuniDatalist(resComune.value, resProv.value, dlResComuni), 180);

        // Eventi
        regimeIva?.addEventListener('change', applyFiscalRules);
        tipoSoggetto?.addEventListener('change', applyFiscalRules);

        birthComune?.addEventListener('input', debouncedBirthComuni);
        birthProv?.addEventListener('input', debouncedBirthComuni);

        resComune?.addEventListener('input', debouncedResComuni);
        resProv?.addEventListener('input', debouncedResComuni);

        // Forza uppercase province
        birthProv?.addEventListener('blur', () => { birthProv.value = normalizeProv(birthProv.value); });
        resProv?.addEventListener('blur', () => { resProv.value = normalizeProv(resProv.value); });

        // Init
        loadProvinceDatalist().finally(() => {
          applyFiscalRules();
        });
      })();
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>

""",
    "admin_inviti.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2>Inviti</h2>
    <button class="btn btn-success" data-bs-toggle="collapse" data-bs-target="#newInvite">Nuovo invito</button>
  </div>

  <div class="collapse mb-3" id="newInvite">
    <div class="card">
      <div class="card-body">
        <form method="post">
          <div class="row g-2">
            <div class="col-md-4">
              <label class="form-label">Scadenza (giorni) opzionale</label>
              <input class="form-control" name="expiry_days" placeholder="Es. 7">
            </div>
            <div class="col-md-3 d-flex align-items-end">
              <button class="btn btn-primary w-100" type="submit">Crea invito</button>
            </div>
          </div>
          <div class="small muted mt-2">Verrà generato un token (URI) + un codice. Il codice scade al primo utilizzo.</div>
        </form>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-body">
      {% if inviti %}
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th>ID</th>
                <th>Link</th>
                <th>Codice</th>
                <th>Creato</th>
                <th>Scadenza</th>
                <th>Stato</th>
                <th>Usato da</th>
                <th style="width: 120px;">Azioni</th>
              </tr>
            </thead>
            <tbody>
              {% for i in inviti %}
                <tr>
                  <td class="small">{{ i.id }}</td>
                  <td class="small">
                    <code class="kv">{{ request.host_url.rstrip('/') }}/invite/{{ i.token }}</code>
                  </td>
                  <td><span class="badge text-bg-dark">{{ i.code }}</span></td>
                  <td class="small">{{ i.created_at.strftime("%Y-%m-%d %H:%M") }}</td>
                  <td class="small">
                    {% if i.expires_at %}
                      {{ i.expires_at.strftime("%Y-%m-%d %H:%M") }}
                    {% else %}
                      -
                    {% endif %}
                  </td>
                  <td>
                    {% if i.used_at %}
                      <span class="badge text-bg-secondary">Usato</span>
                    {% elif i.expires_at and i.is_expired %}
                      <span class="badge text-bg-danger">Scaduto</span>
                    {% else %}
                      <span class="badge text-bg-success">Valido</span>
                    {% endif %}
                  </td>
                  <td class="small">
                    {% if i.used_by_user_id %}
                      ID {{ i.used_by_user_id }}
                    {% else %}
                      -
                    {% endif %}
                  </td>
                  <td>
                    {% if not i.used_at %}
                      <form method="post" action="{{ url_for('admin_inviti_revoke', invite_id=i.id) }}" onsubmit="return confirm('Revocare invito?');">
                        <button class="btn btn-sm btn-outline-danger" type="submit">Revoca</button>
                      </form>
                    {% else %}
                      <span class="muted small">-</span>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <div class="text-muted">Nessun invito.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
""",
    "admin_clients.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2>Clienti</h2>
    <a class="btn btn-success" href="{{ url_for('admin_clients_new') }}">Nuovo cliente</a>
  </div>

  <form class="row g-2 mb-3">
    <div class="col-md-6">
      <input class="form-control" name="q" placeholder="Cerca per ragione sociale..." value="{{ q }}">
    </div>
    <div class="col-md-2">
      <button class="btn btn-outline-primary w-100" type="submit">Cerca</button>
    </div>
    <div class="col-md-2">
      <a class="btn btn-outline-secondary w-100" href="{{ url_for('admin_clients') }}">Reset</a>
    </div>
  </form>

  <div class="card">
    <div class="card-body">
      {% if clients %}
        <div class="list-group">
          {% for c in clients %}
            <a class="list-group-item list-group-item-action" href="{{ url_for('admin_client_detail', client_id=c.id) }}">
              <div class="d-flex justify-content-between">
                <div><strong>{{ c.ragione_sociale }}</strong></div>
                <div class="muted small">ID {{ c.id }}</div>
              </div>
              <div class="small muted">
                {{ c.email or "-" }} | {{ c.telefono or "-" }}
              </div>
            </a>
          {% endfor %}
        </div>
      {% else %}
        <div class="text-muted">Nessun cliente.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
""",
    "admin_clients_new.html": r"""
{% extends "base.html" %}
{% block content %}
  <h2 class="mb-3">Nuovo Cliente</h2>
  <div class="card">
    <div class="card-body">
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Ragione sociale *</label>
          <input class="form-control" name="ragione_sociale" required>
        </div>
        <div class="row g-2">
          <div class="col-md-6 mb-3">
            <label class="form-label">Email</label>
            <input class="form-control" name="email">
          </div>
          <div class="col-md-6 mb-3">
            <label class="form-label">Telefono</label>
            <input class="form-control" name="telefono">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Note</label>
          <textarea class="form-control" name="note" rows="3"></textarea>
        </div>
        <div class="d-flex gap-2">
          <button class="btn btn-success" type="submit">Crea</button>
          <a class="btn btn-outline-secondary" href="{{ url_for('admin_clients') }}">Annulla</a>
        </div>
      </form>
    </div>
  </div>
{% endblock %}
""",
    "admin_client_detail.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>{{ client.ragione_sociale }}</h2>
      <div class="muted">{{ client.email or "-" }} | {{ client.telefono or "-" }}</div>
      <div class="muted small">ID {{ client.id }}</div>
    </div>
    <div class="d-flex gap-2">
      <a class="btn btn-success" href="{{ url_for('admin_incarico_new', client_id=client.id) }}">Nuovo incarico</a>
      <form method="post" action="{{ url_for('admin_client_delete', client_id=client.id) }}"
            onsubmit="return confirm('Eliminare cliente e tutto lo storico incarichi/eventi?');">
        <button class="btn btn-danger" type="submit">Elimina cliente</button>
      </form>
    </div>
  </div>

  <div class="card mb-3">
    <div class="card-header">Modifica cliente</div>
    <div class="card-body">
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Ragione sociale *</label>
          <input class="form-control" name="ragione_sociale" value="{{ client.ragione_sociale }}" required>
        </div>
        <div class="row g-2">
          <div class="col-md-6 mb-3">
            <label class="form-label">Email</label>
            <input class="form-control" name="email" value="{{ client.email or '' }}">
          </div>
          <div class="col-md-6 mb-3">
            <label class="form-label">Telefono</label>
            <input class="form-control" name="telefono" value="{{ client.telefono or '' }}">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Note</label>
          <textarea class="form-control" name="note" rows="3">{{ client.note or '' }}</textarea>
        </div>
        <button class="btn btn-primary" type="submit">Salva</button>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-header d-flex justify-content-between align-items-center">
      <div>Storico incarichi</div>
      <div class="small muted">Totale: {{ incarichi|length }}</div>
    </div>
    <div class="card-body">
      {% if incarichi %}
        <div class="list-group">
          {% for inc in incarichi %}
            <a class="list-group-item list-group-item-action" href="{{ url_for('admin_incarico_detail', incarico_id=inc.id) }}">
              <div class="d-flex justify-content-between">
                <div><strong>{{ inc.titolo }}</strong></div>
                <div class="muted small">ID {{ inc.id }}</div>
              </div>
              <div class="small muted">
                Stato: {{ inc.stato }}{% if inc.descrizione %} | {{ inc.descrizione }}{% endif %}
              </div>
            </a>
          {% endfor %}
        </div>
      {% else %}
        <div class="text-muted">Nessun incarico.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
""",
    "admin_incarico_new.html": r"""
{% extends "base.html" %}
{% block content %}
  <h2 class="mb-3">Nuovo Incarico</h2>
  <div class="mb-3 muted">Cliente: <strong>{{ client.ragione_sociale }}</strong> (ID {{ client.id }})</div>
  <div class="card">
    <div class="card-body">
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Titolo *</label>
          <input class="form-control" name="titolo" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Descrizione</label>
          <textarea class="form-control" name="descrizione" rows="3"></textarea>
        </div>
        <div class="mb-3">
          <label class="form-label">Stato</label>
          <select class="form-select" name="stato">
            <option selected>Attivo</option>
            <option>Chiuso</option>
          </select>
        </div>
        <div class="d-flex gap-2">
          <button class="btn btn-success" type="submit">Crea</button>
          <a class="btn btn-outline-secondary" href="{{ url_for('admin_client_detail', client_id=client.id) }}">Annulla</a>
        </div>
      </form>
    </div>
  </div>
{% endblock %}
""",
    "admin_incarico_detail.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>{{ incarico.titolo }}</h2>
      <div class="muted">Cliente: <a href="{{ url_for('admin_client_detail', client_id=incarico.cliente.id) }}">{{ incarico.cliente.ragione_sociale }}</a></div>
      <div class="muted small">Incarico ID {{ incarico.id }}</div>
    </div>
    <div class="d-flex gap-2">
      <a class="btn btn-primary" href="{{ url_for('admin_incarico_calendar', incarico_id=incarico.id) }}">Apri calendario</a>
      <form method="post" action="{{ url_for('admin_incarico_delete', incarico_id=incarico.id) }}"
            onsubmit="return confirm('Eliminare incarico e calendario/eventi associati?');">
        <button class="btn btn-danger" type="submit">Elimina incarico</button>
      </form>
    </div>
  </div>

  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Opzionate</div>
          <div class="h4 mb-0">{{ "%.2f"|format(stats.opzionate_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.opzionate_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Confermate</div>
          <div class="h4 mb-0">{{ "%.2f"|format(stats.confermate_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.confermate_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Totali</div>
          <div class="h4 mb-0">{{ "%.2f"|format(stats.totale_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.totale_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Stato incarico</div>
          <div class="h4 mb-0">{{ incarico.stato }}</div>
          <div class="muted small">Cliente: {{ incarico.cliente.ragione_sociale }}</div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Modifica incarico</div>
    <div class="card-body">
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Titolo *</label>
          <input class="form-control" name="titolo" value="{{ incarico.titolo }}" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Descrizione</label>
          <textarea class="form-control" name="descrizione" rows="3">{{ incarico.descrizione or '' }}</textarea>
        </div>
        <div class="mb-3">
          <label class="form-label">Stato</label>
          <select class="form-select" name="stato">
            <option {% if incarico.stato=='Attivo' %}selected{% endif %}>Attivo</option>
            <option {% if incarico.stato=='Chiuso' %}selected{% endif %}>Chiuso</option>
          </select>
        </div>
        <button class="btn btn-success" type="submit">Salva</button>
      </form>
    </div>
  </div>
{% endblock %}
""",
    "admin_incarico_calendar.html": r"""
{% extends "base.html" %}

{% block head %}
  <link href="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.15/index.global.min.css" rel="stylesheet">
  <style>
    .sticky-toolbar {
      position: sticky;
      top: 70px;           /* header navbar offset (base.html padding-top:70px) */
      z-index: 2;
      background: var(--bs-body-bg);
      border-bottom: 1px solid var(--bs-border-color);
    }
    .table thead th { vertical-align: middle; }
    .event-title { line-height: 1.2; }
    .event-sub { white-space: pre-line; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      padding: .25rem .5rem;
      border: 1px solid var(--bs-border-color);
      border-radius: 999px;
      font-size: .825rem;
      color: var(--bs-body-color);
      background: var(--bs-body-bg);
    }
  </style>
{% endblock %}

{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>Calendario Incarico</h2>
      <div><strong>{{ incarico.titolo }}</strong></div>
      <div class="muted">
        Cliente:
        <a href="{{ url_for('admin_client_detail', client_id=incarico.cliente.id) }}">{{ incarico.cliente.ragione_sociale }}</a>
      </div>
      <div class="muted small">Incarico ID {{ incarico.id }}</div>
    </div>
    <div class="d-flex gap-2">
      <a class="btn btn-outline-secondary" href="{{ url_for('admin_incarico_detail', incarico_id=incarico.id) }}">Torna incarico</a>
    </div>
  </div>

  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Opzionate</div>
          <div class="h5 mb-0">{{ "%.2f"|format(stats.opzionate_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.opzionate_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Confermate</div>
          <div class="h5 mb-0">{{ "%.2f"|format(stats.confermate_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.confermate_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Ore Totali</div>
          <div class="h5 mb-0">{{ "%.2f"|format(stats.totale_ore) }}</div>
          <div class="muted small">Eventi: {{ stats.totale_count }}</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card">
        <div class="card-body">
          <div class="muted small">Filtri attivi</div>
          <div class="small">
            Status: <strong>{{ status_filter if status_filter else "Tutti" }}</strong><br>
            Docente: <strong>
              {% if docente_filter and docente_filter.isdigit() %}
                {% set dsel = (docenti|selectattr("id","equalto",docente_filter|int)|list) %}
                {{ dsel[0].display_name if dsel else ("ID " ~ docente_filter) }}
              {% else %}
                Tutti
              {% endif %}
            </strong>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="card mb-3">
    <div class="card-header d-flex justify-content-between align-items-center">
      <div>Filtri (admin)</div>
      <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('admin_incarico_calendar', incarico_id=incarico.id) }}">Reset</a>
    </div>
    <div class="card-body">
      <form class="row g-2" method="get">
        <div class="col-md-3">
          <label class="form-label">Status</label>
          <select class="form-select" name="status">
            <option value="" {% if not status_filter %}selected{% endif %}>Tutti</option>
            <option value="Opzionato" {% if status_filter=='Opzionato' %}selected{% endif %}>Opzionato</option>
            <option value="Confermato" {% if status_filter=='Confermato' %}selected{% endif %}>Confermato</option>
          </select>
        </div>
        <div class="col-md-5">
          <label class="form-label">Docente</label>
          <select class="form-select" name="docente_id">
            <option value="" {% if not docente_filter %}selected{% endif %}>Tutti</option>
            {% for d in docenti %}
              <option value="{{ d.id }}" {% if docente_filter and docente_filter.isdigit() and d.id == docente_filter|int %}selected{% endif %}>{{ d.display_name }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button class="btn btn-primary w-100" type="submit">Applica</button>
        </div>
      </form>
    </div>
  </div>

  <div class="card mb-3">
    <div class="card-header">Calendario</div>
    <div class="card-body">
      <div id="calendar"></div>
      <div class="small text-muted mt-2">
        Click su un evento per aprire la modifica.
      </div>
    </div>
  </div>

  <div class="row g-3">
    <!-- COLONNA SINISTRA -->
    <div class="col-lg-5">
      <div class="card mb-3">
        <div class="card-header">Crea evento (crea N eventi nel range)</div>
        <div class="card-body">
          <form method="post" action="{{ url_for('admin_event_new', incarico_id=incarico.id) }}">
            <div class="mb-3">
              <label class="form-label">Titolo *</label>
              <input class="form-control" name="titolo" required>
              <div class="small muted mt-1">
                Regola: se Data inizio = Data fine, crea 1 evento. Altrimenti crea 1 evento per ogni giorno nel range.
              </div>
            </div>

            <div class="row g-2">
              <div class="col-md-6 mb-3">
                <label class="form-label">Data inizio *</label>
                <input class="form-control" type="date" name="date_start" required>
              </div>
              <div class="col-md-6 mb-3">
                <label class="form-label">Data fine *</label>
                <input class="form-control" type="date" name="date_end" required>
              </div>
            </div>

            <div class="row g-2">
              <div class="col-md-6 mb-3">
                <label class="form-label">Ora inizio *</label>
                <input class="form-control" type="time" name="time_start" required>
              </div>
              <div class="col-md-6 mb-3">
                <label class="form-label">Ora fine *</label>
                <input class="form-control" type="time" name="time_end" required>
              </div>
            </div>

            <div class="row g-2">
              <div class="col-md-6 mb-3">
                <label class="form-label">Status</label>
                <select class="form-select" name="status">
                  <option selected>Opzionato</option>
                  <option>Confermato</option>
                </select>
              </div>
              <div class="col-md-6 mb-3 d-flex align-items-end">
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="exclude_weekends" id="exw">
                  <label class="form-check-label" for="exw">Escludi sab/dom</label>
                </div>
              </div>
            </div>

            <button class="btn btn-success" type="submit">Crea</button>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-header">Operazioni in blocco</div>
        <div class="card-body">
          <div class="alert alert-info mb-0">
            Le operazioni in blocco sono nel pannello “Azioni rapide” sopra la tabella eventi (colonna destra).
            Seleziona gli eventi e poi scegli l’azione.
          </div>
        </div>
      </div>
    </div>

    <!-- COLONNA DESTRA -->
    <div class="col-lg-7">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <div>Eventi (filtrati)</div>
          <div class="small muted">Totale mostrati: {{ eventi|length }}</div>
        </div>

        <div class="card-body">
          {% if eventi %}
            <form id="bulkEventsForm" method="post">
              <!-- Toolbar sticky -->
              <div class="sticky-toolbar pt-2 pb-2 mb-3">
                <div class="d-flex flex-wrap gap-2 align-items-center justify-content-between">
                  <div class="d-flex flex-wrap gap-2 align-items-center">
                    <span class="chip">
                      Selezionati: <strong><span id="selCount">0</span></strong>
                    </span>

                    <button class="btn btn-sm btn-outline-primary" type="button"
                            data-bs-toggle="collapse" data-bs-target="#bulkAssignPanel"
                            aria-expanded="false" aria-controls="bulkAssignPanel">
                      Assegna docenti
                    </button>

                    <button class="btn btn-sm btn-outline-secondary" type="button"
                            data-bs-toggle="collapse" data-bs-target="#bulkEditPanel"
                            aria-expanded="false" aria-controls="bulkEditPanel">
                      Modifica in blocco
                    </button>
                  </div>

                  <div class="d-flex flex-wrap gap-2 align-items-center">
                    <button class="btn btn-sm btn-outline-danger" type="submit"
                            formaction="{{ url_for('admin_bulk_delete_events', incarico_id=incarico.id) }}"
                            onclick="return confirm('Eliminare definitivamente gli eventi selezionati?');">
                      Elimina selezionati
                    </button>
                  </div>
                </div>
              </div>

              <!-- Pannello: Assegna docenti -->
              <div class="collapse mb-3" id="bulkAssignPanel">
                <div class="card border">
                  <div class="card-header d-flex justify-content-between align-items-center">
                    <div>Assegna docenti</div>
                    <button type="button" class="btn btn-sm btn-outline-secondary"
                            data-bs-toggle="collapse" data-bs-target="#bulkAssignPanel">
                      Chiudi
                    </button>
                  </div>
                  <div class="card-body">
                    <div class="row g-2">
                      <div class="col-lg-8">
                        <label class="form-label">Docenti (CTRL/CMD per selezione multipla)</label>
                        <select class="form-select" id="bulkAssignDocenti" name="docente_ids" multiple size="7">
                          {% for d in docenti %}
                            <option value="{{ d.id }}">{{ d.display_name }}{% if d.email %} ({{ d.email }}){% endif %}</option>
                          {% endfor %}
                        </select>
                        <div class="form-text">
                          Vincolo: se esiste almeno un conflitto di sovrapposizione, l’operazione viene bloccata.
                        </div>
                      </div>
                      <div class="col-lg-4 d-flex align-items-end">
                        <button class="btn btn-primary w-100" type="submit"
                                formaction="{{ url_for('admin_bulk_assign', incarico_id=incarico.id) }}">
                          Applica assegnazione
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Pannello: Modifica in blocco -->
              <div class="collapse mb-3" id="bulkEditPanel">
                <div class="card border">
                  <div class="card-header d-flex justify-content-between align-items-center">
                    <div>Modifica in blocco</div>
                    <button type="button" class="btn btn-sm btn-outline-secondary"
                            data-bs-toggle="collapse" data-bs-target="#bulkEditPanel">
                      Chiudi
                    </button>
                  </div>

                  <div class="card-body">
                    <div class="alert alert-info">
                      Le modifiche vengono applicate solo ai campi compilati/selezionati. I controlli sui conflitti docenti sono mantenuti lato server.
                    </div>

                    <div class="row g-3">
                      <!-- Titolo / Note -->
                      <div class="col-lg-6">
                        <label class="form-label">Titolo (opzionale)</label>
                        <input class="form-control" name="bulk_titolo" placeholder="Nuovo titolo (se vuoi sovrascrivere)">
                      </div>
                      <div class="col-lg-6">
                        <label class="form-label">Note (opzionale)</label>
                        <textarea class="form-control" name="bulk_note" rows="2" placeholder="Nuove note (se vuoi sovrascrivere)"></textarea>
                        <div class="form-check mt-2">
                          <input class="form-check-input" type="checkbox" name="bulk_clear_note" id="bulkClearNote">
                          <label class="form-check-label" for="bulkClearNote">Svuota note (ignora campo note)</label>
                        </div>
                      </div>

                      <!-- Docenti -->
                      <div class="col-lg-6">
                        <label class="form-label">Docenti: operazione</label>
                        <select class="form-select" name="bulk_docenti_action" id="bulkDocAction">
                          <option value="no_change" selected>Nessuna modifica</option>
                          <option value="replace">Sostituisci docenti assegnati</option>
                          <option value="add">Aggiungi docenti (mantieni gli attuali)</option>
                          <option value="clear">Rimuovi tutti i docenti</option>
                        </select>
                        <div class="form-text">
                          Se scegli “Sostituisci” o “Aggiungi”, seleziona i docenti sotto.
                        </div>
                      </div>
                      <div class="col-lg-6">
                        <label class="form-label">Selezione docenti (solo per Aggiungi/Sostituisci)</label>
                        <select class="form-select" name="bulk_docente_ids" id="bulkEditDocenti" multiple size="6">
                          {% for d in docenti %}
                            <option value="{{ d.id }}">{{ d.display_name }}{% if d.email %} ({{ d.email }}){% endif %}</option>
                          {% endfor %}
                        </select>
                      </div>

                      <!-- Date/ore -->
                      <div class="col-12">
                        <hr>
                        <div class="d-flex flex-wrap gap-2 align-items-center justify-content-between">
                          <div>
                            <div class="fw-semibold">Modifica data/ora</div>
                            <div class="small muted">Scegli una modalità. Se non vuoi toccare gli orari, lascia “Nessuna modifica”.</div>
                          </div>
                        </div>
                      </div>

                      <div class="col-lg-4">
                        <label class="form-label">Modalità</label>
                        <select class="form-select" name="bulk_dt_mode" id="bulkDtMode">
                          <option value="no_change" selected>Nessuna modifica</option>
                          <option value="keep_date_set_time">Mantieni data, imposta orari</option>
                          <option value="shift">Shift (giorni/minuti)</option>
                          <option value="set_absolute">Imposta start/end assoluti (uguali per tutti)</option>
                        </select>
                      </div>

                      <!-- keep_date_set_time -->
                      <div class="col-lg-4">
                        <label class="form-label">Ora inizio (bulk)</label>
                        <input class="form-control" type="time" name="bulk_time_start" id="bulkTimeStart">
                      </div>
                      <div class="col-lg-4">
                        <label class="form-label">Ora fine (bulk)</label>
                        <input class="form-control" type="time" name="bulk_time_end" id="bulkTimeEnd">
                      </div>

                      <!-- shift -->
                      <div class="col-lg-6">
                        <label class="form-label">Shift giorni (es. 1, -1)</label>
                        <input class="form-control" type="number" name="bulk_shift_days" id="bulkShiftDays" value="0">
                      </div>
                      <div class="col-lg-6">
                        <label class="form-label">Shift minuti (es. 30, -15)</label>
                        <input class="form-control" type="number" name="bulk_shift_minutes" id="bulkShiftMinutes" value="0">
                      </div>

                      <!-- set_absolute -->
                      <div class="col-lg-6">
                        <label class="form-label">Start assoluto</label>
                        <input class="form-control" type="datetime-local" name="bulk_abs_start_dt" id="bulkAbsStart">
                      </div>
                      <div class="col-lg-6">
                        <label class="form-label">End assoluto</label>
                        <input class="form-control" type="datetime-local" name="bulk_abs_end_dt" id="bulkAbsEnd">
                      </div>

                      <div class="col-12">
                        <button class="btn btn-success" type="submit"
                                formaction="{{ url_for('admin_bulk_update_events', incarico_id=incarico.id) }}">
                          Applica modifiche in blocco
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Tabella eventi -->
              <div class="table-responsive">
                <table class="table table-sm align-middle">
                  <thead>
                    <tr>
                      <th style="width: 44px;" class="text-center">
                        <input class="form-check-input" type="checkbox" id="selAll">
                      </th>
                      <th>Evento</th>
                      <th>Slot</th>
                      <th>Status</th>
                      <th>Docenti</th>
                      <th style="width: 170px;">Azioni</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for e in eventi %}
                      <tr>
                        <td class="text-center">
                          <input class="form-check-input event-sel" type="checkbox" name="event_ids" value="{{ e.id }}">
                        </td>
                        <td>
                          <div class="event-title">
                            <strong>{{ e.titolo }}</strong>
                          </div>
                          <div class="small muted event-sub">
                            ID {{ e.id }}
                            {% if e.note %}
                              <br>Note: {{ e.note }}
                            {% endif %}
                          </div>
                        </td>
                        <td class="small">
                          {{ e.start_dt.strftime("%Y-%m-%d %H:%M") }}<br>
                          {{ e.end_dt.strftime("%Y-%m-%d %H:%M") }}
                        </td>
                        <td>
                          {% if e.status == "Confermato" %}
                            <span class="badge text-bg-success">Confermato</span>
                          {% else %}
                            <span class="badge text-bg-secondary">Opzionato</span>
                          {% endif %}
                        </td>
                        <td class="small">
                          {% if e.docenti %}
                            {% for d in e.docenti %}
                              <div>{{ d.display_name }}</div>
                            {% endfor %}
                          {% else %}
                            <span class="muted">-</span>
                          {% endif %}
                        </td>
                        <td>
                          <a class="btn btn-sm btn-outline-primary" href="{{ url_for('admin_event_edit', event_id=e.id) }}">Modifica</a>
                          <form class="d-inline" method="post" action="{{ url_for('admin_event_delete', event_id=e.id) }}"
                                onsubmit="return confirm('Eliminare evento?');">
                            <button class="btn btn-sm btn-outline-danger" type="submit">Elimina</button>
                          </form>
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>

              <div class="small muted mt-2">
                Suggerimento: usa “Seleziona tutti” e poi apri “Azioni rapide” per operazioni in blocco.
              </div>
            </form>
          {% else %}
            <div class="text-muted">Nessun evento in base ai filtri correnti.</div>
          {% endif %}
        </div>
      </div>
    </div>
  </div>
{% endblock %}

{% block scripts %}
  <script src="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.15/index.global.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // =========================
      // FullCalendar
      // =========================
      const calendarEl = document.getElementById('calendar');
      const params = new URLSearchParams(window.location.search);
      const status = params.get('status') || '';
      const docente_id = params.get('docente_id') || '';

      const eventsUrl = new URL('{{ url_for("admin_incarico_events_json", incarico_id=incarico.id) }}', window.location.origin);
      if (status) eventsUrl.searchParams.set('status', status);
      if (docente_id) eventsUrl.searchParams.set('docente_id', docente_id);

      const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'timeGridWeek',
        height: 650,
        nowIndicator: true,
        firstDay: 1,
        slotMinTime: '07:00:00',
        slotMaxTime: '21:00:00',
        allDaySlot: false,
        events: eventsUrl.toString(),
        eventClick: function(info) {
          window.location.href = '/admin/events/' + info.event.id + '/edit';
        }
      });
      calendar.render();

      // =========================
      // Bulk UX helpers
      // =========================
      const form = document.getElementById('bulkEventsForm');
      if (!form) return;

      const selAll = document.getElementById('selAll');
      const selCountEl = document.getElementById('selCount');

      function selectedBoxes() {
        return Array.from(form.querySelectorAll('.event-sel')).filter(cb => cb.checked);
      }
      function updateSelectedCount() {
        selCountEl.textContent = String(selectedBoxes().length);
      }

      selAll.addEventListener('change', function() {
        const cbs = form.querySelectorAll('.event-sel');
        cbs.forEach(cb => { cb.checked = selAll.checked; });
        updateSelectedCount();
      });

      form.querySelectorAll('.event-sel').forEach(cb => {
        cb.addEventListener('change', function() {
          const cbs = Array.from(form.querySelectorAll('.event-sel'));
          const allChecked = cbs.length > 0 && cbs.every(x => x.checked);
          selAll.checked = allChecked;
          updateSelectedCount();
        });
      });

      updateSelectedCount();

      // Client-side validation by submit button
      form.addEventListener('submit', function(ev) {
        const submitter = ev.submitter;
        if (!submitter) return;

        const action = submitter.getAttribute('formaction') || '';
        const selected = selectedBoxes().length;

        if (selected === 0) {
          ev.preventDefault();
          alert('Seleziona almeno un evento.');
          return;
        }

        // Bulk assign validation
        if (action.includes('/assign')) {
          const sel = document.getElementById('bulkAssignDocenti');
          const docSelected = sel ? Array.from(sel.options).some(o => o.selected) : false;
          if (!docSelected) {
            ev.preventDefault();
            alert('Seleziona almeno un docente per l’assegnazione.');
            return;
          }
        }

        // Bulk update minimal validation (lascia i dettagli al server, ma evita casi vuoti)
        if (action.includes('/bulk_update')) {
          const titolo = (form.querySelector('[name="bulk_titolo"]')?.value || '').trim();
          const note = (form.querySelector('[name="bulk_note"]')?.value || '').trim();
          const clearNote = !!form.querySelector('[name="bulk_clear_note"]')?.checked;

          const docAction = form.querySelector('[name="bulk_docenti_action"]')?.value || 'no_change';
          const dtMode = form.querySelector('[name="bulk_dt_mode"]')?.value || 'no_change';

          const hasAny =
            !!titolo ||
            !!note ||
            clearNote ||
            (docAction !== 'no_change') ||
            (dtMode !== 'no_change');

          if (!hasAny) {
            ev.preventDefault();
            alert('Compila almeno un campo o seleziona una modifica (docenti/data-ora) prima di applicare.');
            return;
          }

          if (docAction === 'replace' || docAction === 'add') {
            const dsel = document.getElementById('bulkEditDocenti');
            const ok = dsel ? Array.from(dsel.options).some(o => o.selected) : false;
            if (!ok) {
              ev.preventDefault();
              alert('Seleziona i docenti per l’azione scelta (Aggiungi/Sostituisci).');
              return;
            }
          }

          if (dtMode === 'keep_date_set_time') {
            const ts = (document.getElementById('bulkTimeStart')?.value || '').trim();
            const te = (document.getElementById('bulkTimeEnd')?.value || '').trim();
            if (!ts || !te) {
              ev.preventDefault();
              alert('Per “Mantieni data, imposta orari” devi compilare Ora inizio e Ora fine.');
              return;
            }
          }

          if (dtMode === 'set_absolute') {
            const as = (document.getElementById('bulkAbsStart')?.value || '').trim();
            const ae = (document.getElementById('bulkAbsEnd')?.value || '').trim();
            if (!as || !ae) {
              ev.preventDefault();
              alert('Per “Imposta start/end assoluti” devi compilare Start assoluto e End assoluto.');
              return;
            }
          }

          if (dtMode === 'shift') {
            const sd = parseInt(document.getElementById('bulkShiftDays')?.value || '0', 10);
            const sm = parseInt(document.getElementById('bulkShiftMinutes')?.value || '0', 10);
            if ((sd === 0) && (sm === 0)) {
              ev.preventDefault();
              alert('Per “Shift” inserisci almeno un valore diverso da 0 tra giorni e minuti.');
              return;
            }
          }
        }
      });
    });
  </script>
{% endblock %}

""",
    "admin_event_edit.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>Modifica Evento</h2>
      <div class="muted">Incarico: <a href="{{ url_for('admin_incarico_calendar', incarico_id=incarico.id) }}">{{ incarico.titolo }}</a></div>
      <div class="muted small">Evento ID {{ evento.id }}</div>
    </div>
    <div class="d-flex gap-2">
      <a class="btn btn-outline-secondary" href="{{ url_for('admin_incarico_calendar', incarico_id=incarico.id) }}">Torna calendario</a>
    </div>
  </div>

  <div class="card">
    <div class="card-body">
      <div class="alert alert-info">
        Vincolo docenti: non è possibile assegnare docenti che abbiano già eventi sovrapposti nello stesso slot.
      </div>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Titolo *</label>
          <input class="form-control" name="titolo" value="{{ evento.titolo }}" required>
        </div>

        <div class="mb-3">
          <label class="form-label">Note</label>
          <textarea class="form-control" name="note" rows="3">{{ evento.note or '' }}</textarea>
        </div>

        <div class="row g-2">
          <div class="col-md-6 mb-3">
            <label class="form-label">Inizio *</label>
            <input class="form-control" type="datetime-local" name="start_dt"
                   value="{{ evento.start_dt.strftime('%Y-%m-%dT%H:%M') }}" required>
          </div>
          <div class="col-md-6 mb-3">
            <label class="form-label">Fine *</label>
            <input class="form-control" type="datetime-local" name="end_dt"
                   value="{{ evento.end_dt.strftime('%Y-%m-%dT%H:%M') }}" required>
          </div>
        </div>

        <div class="mb-3">
          <label class="form-label">Status</label>
          <select class="form-select" name="status">
            <option {% if evento.status=='Opzionato' %}selected{% endif %}>Opzionato</option>
            <option {% if evento.status=='Confermato' %}selected{% endif %}>Confermato</option>
          </select>
        </div>

        <div class="mb-3">
          <label class="form-label">Docenti assegnati (sostituisce l'insieme corrente)</label>
          <select class="form-select" name="docente_ids" multiple size="8">
            {% set current_ids = evento.docenti|map(attribute='id')|list %}
            {% for d in docenti %}
              <option value="{{ d.id }}" {% if d.id in current_ids %}selected{% endif %}>
                {{ d.display_name }}{% if d.email %} ({{ d.email }}){% endif %}
              </option>
            {% endfor %}
          </select>
          <div class="small muted mt-1">CTRL/CMD per selezione multipla.</div>
        </div>

        <button class="btn btn-success" type="submit">Salva</button>
      </form>
    </div>
  </div>
{% endblock %}
""",
    "admin_docenti.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2>Docenti</h2>
  </div>

  <form class="row g-2 mb-3">
    <div class="col-md-6">
      <input class="form-control" name="q" placeholder="Cerca per nome/cognome/email/CF/RS..." value="{{ q }}">
    </div>
    <div class="col-md-2">
      <button class="btn btn-outline-primary w-100" type="submit">Cerca</button>
    </div>
    <div class="col-md-2">
      <a class="btn btn-outline-secondary w-100" href="{{ url_for('admin_docenti') }}">Reset</a>
    </div>
  </form>

  <div class="card">
    <div class="card-body">
      {% if docenti %}
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th>ID</th>
                <th>Docente</th>
                <th>Email</th>
                <th>Tipo</th>
                <th>CF</th>
                <th>Ragione sociale</th>
                <th>Account</th>
                <th style="width: 130px;">Azioni</th>
              </tr>
            </thead>
            <tbody>
              {% for d in docenti %}
                <tr>
                  <td class="small">{{ d.id }}</td>
                  <td><strong>{{ d.display_name }}</strong></td>
                  <td class="small">{{ d.email or "-" }}</td>
                  <td class="small">{{ d.tipo_soggetto }}</td>
                  <td class="small">{{ d.codice_fiscale or "-" }}</td>
                  <td class="small">{{ d.ragione_sociale or "-" }}</td>
                  <td class="small">
                    {% if d.user %}
                      {{ d.user.username }} ({{ d.user.status }})
                    {% else %}
                      -
                    {% endif %}
                  </td>
                  <td>
                    <a class="btn btn-sm btn-outline-primary" href="{{ url_for('admin_docente_detail', docente_id=d.id) }}">Apri</a>
                    <form class="d-inline" method="post" action="{{ url_for('admin_docenti_delete', docente_id=d.id) }}"
                          onsubmit="return confirm('Eliminare docente e user associato?');">
                      <button class="btn btn-sm btn-outline-danger" type="submit">Elimina</button>
                    </form>
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <div class="text-muted">Nessun docente.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
""",
    "admin_docente_detail.html": r"""
<!doctype html>
<html lang="it">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin · Dettaglio Docente - {{ app_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-top: 26px; }
      .card { border: 0; }
      .card.shadow-soft { box-shadow: 0 .25rem .9rem rgba(0,0,0,.06); }
      .section-title { font-size: 1.05rem; font-weight: 600; }
      .section-sub { color: #6c757d; font-size: .92rem; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .req::after { content: " *"; color: #dc3545; font-weight: 700; }
      .help { color: #6c757d; font-size: .9rem; }
      .badge-soft { background: rgba(13,110,253,.12); color: #0d6efd; }
      .kv { font-size: .95rem; }
      .kv b { font-weight: 600; }
      .hr-soft { border-top: 1px solid rgba(0,0,0,.08); }
      .small-muted { color: #6c757d; font-size: .9rem; }
      .cv-frame { width: 100%; height: 680px; border: 1px solid rgba(0,0,0,.08); border-radius: 12px; }
    </style>
  </head>

  <body class="bg-light">
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-12 col-xl-10">
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
            <div>
              <h3 class="mb-1">Dettaglio Docente</h3>
              <div class="text-muted">
                Gestione anagrafica, inquadramento fiscale e dati amministrativi.
              </div>
            </div>
            <div class="d-flex flex-wrap gap-2">
              <a class="btn btn-outline-secondary" href="{{ url_for('admin_docenti') }}">Torna ai docenti</a>
              <a class="btn btn-outline-dark" href="{{ url_for('logout') }}">Logout</a>
            </div>
          </div>

          {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
              {% for cat, msg in messages %}
                <div class="alert alert-{{ cat }} mb-3">{{ msg }}</div>
              {% endfor %}
            {% endif %}
          {% endwith %}

          <div class="row g-3">
            <!-- Colonna sinistra: riepilogo -->
            <div class="col-12 col-lg-4">
              <div class="card shadow-soft">
                <div class="card-body p-4">
                  <div class="d-flex justify-content-between align-items-start">
                    <div>
                      <div class="section-title mb-1">{{ docente.nome }} {{ docente.cognome }}</div>
                      <div class="small-muted">
                        Docente ID: <span class="mono">{{ docente.id }}</span>
                      </div>
                    </div>
                    <span class="badge badge-soft">
                      {{ (user.status or '—')|upper }}
                    </span>
                  </div>

                  <hr class="hr-soft my-3">

                  <div class="kv mb-2">
                    <div><b>Username</b></div>
                    <div class="mono">{{ user.username }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Ruolo</b></div>
                    <div>{{ user.role or '—' }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Email</b></div>
                    <div>{{ docente.email or '—' }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Telefono</b></div>
                    <div>{{ docente.cellulare or docente.telefono or '—' }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Tipo soggetto</b></div>
                    <div>{{ docente.tipo_soggetto or '—' }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Regime IVA / Tipo P.IVA</b></div>
                    <div>{{ docente.regime_iva or '—' }}</div>
                  </div>

                  <div class="kv mb-2">
                    <div><b>Partita IVA</b></div>
                    <div class="mono">{{ docente.partita_iva or '—' }}</div>
                  </div>

                  <hr class="hr-soft my-3">

                  <div class="kv">
                    <div><b>CV</b></div>
                    {% if docente.cv_filename %}
                      <div class="mono">{{ docente.cv_filename }}</div>
                      {% if docente.cv_uploaded_at %}
                        <div class="small-muted mt-1">Caricato il: {{ docente.cv_uploaded_at }}</div>
                      {% endif %}

                      <div class="d-grid gap-2 mt-3">
                        <a class="btn btn-outline-primary"
                           href="{{ url_for('admin_docente_cv', docente_id=docente.id, download=0) }}"
                           target="_blank" rel="noopener">
                          Apri CV (view)
                        </a>
                        <a class="btn btn-outline-secondary"
                           href="{{ url_for('admin_docente_cv', docente_id=docente.id, download=1) }}">
                          Scarica CV
                        </a>
                        <button class="btn btn-outline-dark" type="button"
                                data-bs-toggle="collapse" data-bs-target="#cvInline"
                                aria-expanded="false" aria-controls="cvInline">
                          Anteprima in pagina
                        </button>
                      </div>
                    {% else %}
                      <div>—</div>
                    {% endif %}
                  </div>
                </div>
              </div>
            </div>

            <!-- Colonna destra: form -->
            <div class="col-12 col-lg-8">
              <div class="card shadow-soft mb-3">
                <div class="card-body p-4 p-lg-5">

                  <!-- ANTEPRIMA CV INLINE -->
                  {% if docente.cv_filename %}
                    <div class="collapse mb-4" id="cvInline">
                      <div class="alert alert-info">
                        Se il browser non supporta l’anteprima PDF, usa “Apri CV (view)” oppure “Scarica CV”.
                      </div>
                      <iframe class="cv-frame"
                              src="{{ url_for('admin_docente_cv', docente_id=docente.id, download=0) }}"></iframe>
                      <hr class="my-4">
                    </div>
                  {% endif %}

                  <form method="post" enctype="multipart/form-data" action="{{ url_for('admin_docente_detail', docente_id=docente.id) }}" novalidate>
                    <!-- SEZIONE: Stato account -->
                    <div class="mb-3">
                      <div class="section-title">Stato account</div>
                      <div class="section-sub">Gestione stato utente.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-md-6">
                        <label class="form-label">Status</label>
                        <select class="form-select" name="user_status">
                          {% set st = (user.status or '') %}
                          <option value="pending" {% if st == 'pending' %}selected{% endif %}>pending</option>
                          <option value="active" {% if st == 'active' %}selected{% endif %}>active</option>
                          <option value="disabled" {% if st == 'disabled' %}selected{% endif %}>disabled</option>
                        </select>
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Attivo</label>
                        <div class="form-check mt-2">
                          {% set is_active = user.is_active if user.is_active is not none else (user.status == 'active') %}
                          <input class="form-check-input" type="checkbox" id="isActive" name="is_active" value="1" {% if is_active %}checked{% endif %}>
                          <label class="form-check-label" for="isActive">Utente attivo</label>
                        </div>
                        <div class="help mt-1">Se non usi <span class="mono">is_active</span>, ignora questa opzione.</div>
                      </div>
                    </div>

                    <hr class="my-4">

                    <!-- SEZIONE: Anagrafica -->
                    <div class="mb-3">
                      <div class="section-title">Anagrafica</div>
                      <div class="section-sub">Dati personali del docente.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-md-6">
                        <label class="form-label req">Nome</label>
                        <input class="form-control" name="nome" value="{{ docente.nome or '' }}" required>
                      </div>

                      <div class="col-md-6">
                        <label class="form-label req">Cognome</label>
                        <input class="form-control" name="cognome" value="{{ docente.cognome or '' }}" required>
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Email</label>
                        <input class="form-control" name="email" type="email" value="{{ docente.email or '' }}">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Telefono (cellulare)</label>
                        <input class="form-control" name="cellulare" value="{{ docente.cellulare or docente.telefono or '' }}">
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Sesso</label>
                        <select class="form-select" name="sesso">
                          {% set sx = docente.sesso or '' %}
                          <option value="" {% if sx == '' %}selected{% endif %}>—</option>
                          <option value="M" {% if sx == 'M' %}selected{% endif %}>M</option>
                          <option value="F" {% if sx == 'F' %}selected{% endif %}>F</option>
                          <option value="Altro" {% if sx == 'Altro' %}selected{% endif %}>Altro</option>
                        </select>
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Codice Fiscale</label>
                        <input class="form-control mono" name="codice_fiscale" value="{{ docente.codice_fiscale or '' }}">
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Data di nascita</label>
                        <input class="form-control" type="date" name="data_nascita"
                          value="{% if docente.data_nascita %}{{ docente.data_nascita.strftime('%Y-%m-%d') }}{% endif %}">
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Luogo di nascita</label>
                        <input class="form-control" name="luogo_nascita" value="{{ docente.luogo_nascita or '' }}" placeholder="Comune (PR)">
                        <div class="help mt-1">Formato suggerito: Comune (PR)</div>
                      </div>
                    </div>

                    <hr class="my-4">

                    <!-- SEZIONE: Inquadramento -->
                    <div class="mb-3">
                      <div class="section-title">Inquadramento fiscale</div>
                      <div class="section-sub">Tipo soggetto, regime IVA e Partita IVA.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-md-6">
                        <label class="form-label">Tipo soggetto</label>
                        <select class="form-select" name="tipo_soggetto" id="tipoSoggetto">
                          {% set ts = docente.tipo_soggetto or 'Libero Professionista' %}
                          <option value="Libero Professionista" {% if ts == 'Libero Professionista' %}selected{% endif %}>Libero Professionista</option>
                          <option value="Azienda" {% if ts == 'Azienda' %}selected{% endif %}>Azienda</option>
                        </select>
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Ragione sociale</label>
                        <input class="form-control" name="ragione_sociale" id="ragioneSociale" value="{{ docente.ragione_sociale or '' }}">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Regime IVA / Tipo P.IVA</label>
                        <select class="form-select" name="regime_iva" id="regimeIva">
                          <option value="" {% if not docente.regime_iva %}selected{% endif %}>—</option>
                          {% if regime_iva_choices %}
                            {% for opt in regime_iva_choices %}
                              <option value="{{ opt }}" {% if docente.regime_iva == opt %}selected{% endif %}>{{ opt }}</option>
                            {% endfor %}
                          {% else %}
                            <option value="Partita Iva in Regime dei minimi / agevolato / forfettario" {% if docente.regime_iva == "Partita Iva in Regime dei minimi / agevolato / forfettario" %}selected{% endif %}>Partita Iva in Regime dei minimi / agevolato / forfettario</option>
                            <option value="R.A. secca" {% if docente.regime_iva == "R.A. secca" %}selected{% endif %}>R.A. secca</option>
                            <option value="P.I. senza R.A. (es: ditta individuale, srl, spa...)" {% if docente.regime_iva == "P.I. senza R.A. (es: ditta individuale, srl, spa...)" %}selected{% endif %}>P.I. senza R.A. (es: ditta individuale, srl, spa...)</option>
                            <option value="P.I. in ritenuta d'acconto (consulenti)" {% if docente.regime_iva == "P.I. in ritenuta d'acconto (consulenti)" %}selected{% endif %}>P.I. in ritenuta d'acconto (consulenti)</option>
                          {% endif %}
                        </select>
                      </div>

                      <div class="col-md-6">
                        <label class="form-label" id="lblPiva">Partita IVA</label>
                        <input class="form-control mono" name="partita_iva" id="partitaIva" value="{{ docente.partita_iva or '' }}" maxlength="11" placeholder="11 cifre">
                        <div class="help mt-1" id="pivaHelp"></div>
                      </div>
                    </div>

                    <hr class="my-4">

                    <!-- SEZIONE: Residenza -->
                    <div class="mb-3">
                      <div class="section-title">Residenza</div>
                      <div class="section-sub">Indirizzo di residenza.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-md-6">
                        <label class="form-label">Via</label>
                        <input class="form-control" name="res_via" value="{{ docente.res_via or '' }}">
                      </div>

                      <div class="col-md-2">
                        <label class="form-label">Civico</label>
                        <input class="form-control" name="res_civico" value="{{ docente.res_civico or '' }}">
                      </div>

                      <div class="col-md-4">
                        <label class="form-label">CAP</label>
                        <input class="form-control mono" name="res_cap" value="{{ docente.res_cap or '' }}" maxlength="5">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Comune</label>
                        <input class="form-control" name="res_comune" value="{{ docente.res_comune or '' }}">
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Provincia</label>
                        <input class="form-control mono" name="res_provincia" value="{{ docente.res_provincia or '' }}" maxlength="2" placeholder="Es. NA">
                      </div>

                      <div class="col-md-3">
                        <label class="form-label">Nazione</label>
                        <input class="form-control" name="res_nazione" value="{{ docente.res_nazione or 'Italia' }}">
                      </div>
                    </div>

                    <hr class="my-4">

                    <!-- SEZIONE: Banca -->
                    <div class="mb-3">
                      <div class="section-title">Dati bancari</div>
                      <div class="section-sub">Opzionali.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-md-6">
                        <label class="form-label">Banca di appoggio</label>
                        <input class="form-control" name="banca_appoggio" value="{{ docente.banca_appoggio or '' }}">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">Intestatario banca</label>
                        <input class="form-control" name="intestatario_banca" value="{{ docente.intestatario_banca or '' }}">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">IBAN</label>
                        <input class="form-control mono" name="iban" value="{{ docente.iban or '' }}">
                      </div>

                      <div class="col-md-6">
                        <label class="form-label">BIC/SWIFT</label>
                        <input class="form-control mono" name="bic_swift" value="{{ docente.bic_swift or '' }}">
                      </div>
                    </div>

                    <hr class="my-4">

                    <!-- SEZIONE: CV upload (admin) -->
                    <div class="mb-3">
                      <div class="section-title">Curriculum</div>
                      <div class="section-sub">Sostituzione file CV (PDF) tramite backend admin.</div>
                    </div>

                    <div class="row g-3">
                      <div class="col-12">
                        <label class="form-label">Sostituisci CV (PDF)</label>
                        <input class="form-control" type="file" name="cv_pdf" accept="application/pdf">
                        <div class="help mt-1">Caricando un nuovo PDF, sostituisce il precedente.</div>
                      </div>
                    </div>

                    <div class="mt-4 d-flex flex-wrap gap-2">
                      <button class="btn btn-primary px-4" type="submit">Salva modifiche</button>
                      <a class="btn btn-outline-secondary" href="{{ url_for('admin_docenti') }}">Annulla</a>
                    </div>
                  </form>
                </div>
              </div>

              <div class="text-center mt-3 text-muted small">
                {{ app_name }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      (function () {
        const tipoSoggetto = document.getElementById('tipoSoggetto');
        const ragSoc = document.getElementById('ragioneSociale');

        const regimeIva = document.getElementById('regimeIva');
        const piva = document.getElementById('partitaIva');
        const lblPiva = document.getElementById('lblPiva');
        const pivaHelp = document.getElementById('pivaHelp');

        function setRequired(el, required) {
          if (!el) return;
          if (required) el.setAttribute('required', 'required');
          else el.removeAttribute('required');
        }

        function setReqLabel(labelEl, required) {
          if (!labelEl) return;
          if (required) labelEl.classList.add('req');
          else labelEl.classList.remove('req');
        }

        function applyRules() {
          const ts = (tipoSoggetto?.value || '').trim();
          const isAzienda = (ts === 'Azienda');
          setRequired(ragSoc, isAzienda);

          const regime = (regimeIva?.value || '').trim();
          const isRASecca = (regime === "R.A. secca");

          setRequired(piva, !isRASecca);
          setReqLabel(lblPiva, !isRASecca);

          if (pivaHelp) {
            pivaHelp.textContent = isRASecca
              ? "Opzionale per R.A. secca."
              : "Obbligatoria per il regime selezionato (11 cifre).";
          }
        }

        tipoSoggetto?.addEventListener('change', applyRules);
        regimeIva?.addEventListener('change', applyRules);

        applyRules();
      })();
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>


""",
    "docente_dashboard.html": r"""
{% extends "base.html" %}
{% block head %}
  <link href="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.15/index.global.min.css" rel="stylesheet">
{% endblock %}
{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>Area Docente</h2>
      <div><strong>{{ docente.display_name }}</strong></div>
      <div class="muted">{{ docente.email or "" }}</div>
    </div>
  </div>

  <div class="card mb-3">
    <div class="card-header">Calendario lezioni assegnate</div>
    <div class="card-body">
      <div id="calendar"></div>
      <div class="small muted mt-2">
        Click su un evento per aprire l'incarico collegato.
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header d-flex justify-content-between align-items-center">
      <div>Incarichi associati</div>
      <div class="small muted">Totale: {{ incarichi|length }}</div>
    </div>
    <div class="card-body">
      {% if incarichi %}
        <div class="list-group">
          {% for inc in incarichi %}
            <a class="list-group-item list-group-item-action" href="{{ url_for('docente_incarico_detail', incarico_id=inc.id) }}">
              <div class="d-flex justify-content-between">
                <div><strong>{{ inc.titolo }}</strong></div>
                <div class="muted small">ID {{ inc.id }}</div>
              </div>
              <div class="small muted">
                Cliente: {{ inc.cliente.ragione_sociale }} | Stato: {{ inc.stato }}
              </div>
            </a>
          {% endfor %}
        </div>
      {% else %}
        <div class="text-muted">Nessun incarico associato.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
{% block scripts %}
  <script src="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.15/index.global.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const calendarEl = document.getElementById('calendar');
      const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'timeGridWeek',
        height: 650,
        nowIndicator: true,
        firstDay: 1,
        slotMinTime: '07:00:00',
        slotMaxTime: '21:00:00',
        allDaySlot: false,
        events: '{{ url_for("docente_events_json") }}',
        eventClick: function(info) {
          const incId = info.event.extendedProps.incarico_id;
          if (incId) {
            window.location.href = '/docente/incarichi/' + incId;
          }
        }
      });
      calendar.render();
    });
  </script>
{% endblock %}
""",
    "docente_incarico_detail.html": r"""
{% extends "base.html" %}
{% block content %}
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2>Dettaglio Incarico</h2>
      <div><strong>{{ incarico.titolo }}</strong></div>
      <div class="muted">Cliente: {{ incarico.cliente.ragione_sociale }}</div>
      <div class="muted small">Incarico ID {{ incarico.id }}</div>
    </div>
    <div>
      <a class="btn btn-outline-secondary" href="{{ url_for('docente_dashboard') }}">Torna dashboard</a>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Lezioni/eventi assegnati</div>
    <div class="card-body">
      {% if eventi %}
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th>Evento</th>
                <th>Slot</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {% for e in eventi %}
                <tr>
                  <td>
                    <strong>{{ e.titolo }}</strong>
                    <div class="small muted">ID {{ e.id }}</div>
                    {% if e.note %}
                      <div class="small muted">Note: {{ e.note }}</div>
                    {% endif %}
                  </td>
                  <td class="small">
                    {{ e.start_dt.strftime("%Y-%m-%d %H:%M") }} - {{ e.end_dt.strftime("%Y-%m-%d %H:%M") }}
                  </td>
                  <td>
                    {% if e.status == "Confermato" %}
                      <span class="badge text-bg-success">Confermato</span>
                    {% else %}
                      <span class="badge text-bg-secondary">Opzionato</span>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <div class="text-muted">Nessuna lezione assegnata.</div>
      {% endif %}
    </div>
  </div>
{% endblock %}
""",
}