# -*- coding: utf-8 -*-
"""Logica dei consigli per l'upgrade in place di RHEL con Leapp.

Riceve i dati raccolti sul server, i salti di versione pubblicati da Red Hat
(upgrade_paths.json del progetto leapp-repository) e le CVE pubbliche, e
restituisce la procedura passo per passo.

Gira sul controller Ansible: nessuna dipendenza oltre la libreria standard.
"""
from __future__ import absolute_import, division, print_function

import json
import re

DOCS = {
    7: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/index",
    8: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/index",
    9: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/upgrading_from_rhel_9_to_rhel_10/index",
}

# Soglie prudenziali per lo spazio libero (in MB).
MIN_VAR_MB = 5120
MIN_BOOT_MB = 100


def _ver_key(v):
    return tuple(int(p) for p in str(v).split("."))


def _major(v):
    return int(str(v).split(".")[0])


def _tabella(paths, flavour="default"):
    """Accetta sia il formato nuovo ({"rhel": {"default": ...}}) sia quello
    archiviato di RHEL 7 ({"default": ...})."""
    if not paths:
        return {}
    if "rhel" in paths:
        paths = paths["rhel"]
    return paths.get(flavour) or paths.get("default") or {}


def scegli_salto(versione, paths_main, paths_rhel7, flavour="default"):
    """Per una versione sorgente (es. "8.6") restituisce il salto supportato:
    da quale minor bisogna partire e verso quale versione arrivare."""
    major = _major(versione)
    tab = _tabella(paths_rhel7 if major == 7 else paths_main, flavour)
    minori = sorted((k for k in tab if "." in k and _major(k) == major), key=_ver_key)
    if not minori and str(major) in tab:
        minori = [str(major)]
    if not minori:
        return None
    attuale = _ver_key(versione)
    partenza = None
    if str(versione) in minori:
        partenza = str(versione)
    else:
        superiori = [m for m in minori if _ver_key(m) >= attuale]
        partenza = superiori[0] if superiori else minori[-1]
    arrivi = tab.get(partenza) or tab.get(str(major)) or []
    if not arrivi:
        return None
    ordinati = sorted(arrivi, key=_ver_key)
    arrivo = ordinati[-1]
    return {
        "da": str(versione),
        "parti_da": partenza,
        "serve_aggiornare_minor": _ver_key(partenza) > attuale,
        "arrivo": arrivo,
        "possibili": ordinati,
    }


def catena(versione, paths_main, paths_rhel7, major_obiettivo=None, flavour="default"):
    """Elenca tutti i salti dalla versione attuale fino all'obiettivo."""
    salti = []
    corrente = str(versione)
    for _ in range(5):
        if major_obiettivo and _major(corrente) >= int(major_obiettivo):
            break
        s = scegli_salto(corrente, paths_main, paths_rhel7, flavour)
        if not s:
            break
        salti.append(s)
        corrente = s["arrivo"]
    return salti


def _avvisi_sicurezza(righe):
    """Legge l'uscita di 'yum/dnf updateinfo list --security'."""
    out = []
    for r in righe or []:
        m = re.match(r"^\s*(RH[SBE]A-\d{4}:\d+)\s+(\S+?)/Sec\.?\s+(\S+)", r)
        if m:
            out.append({"avviso": m.group(1), "gravita": m.group(2).lower(), "pacchetto": m.group(3)})
    return out


def _blocchi_leapp(report):
    """Estrae dal leapp-report.json i problemi che bloccano l'upgrade."""
    out = []
    for e in (report or {}).get("entries", []):
        gruppi = set(e.get("groups", []) or []) | set(e.get("flags", []) or [])
        if "inhibitor" not in gruppi:
            continue
        rimedi = []
        for r in (e.get("detail", {}) or {}).get("remediations", []) or []:
            ctx = r.get("context")
            if isinstance(ctx, list):
                ctx = " ".join(str(c) for c in ctx)
            rimedi.append({"tipo": r.get("type"), "testo": ctx})
        out.append({"titolo": e.get("title"), "riassunto": e.get("summary"), "rimedi": rimedi})
    return out


def _nome_pacchetto(nvr):
    """'openssl-1:3.0.7-28.el9_4' -> 'openssl'."""
    parti = str(nvr).rsplit("-", 2)
    return parti[0] if len(parti) == 3 else str(nvr)


def cve_del_server(cve, installati, major=None):
    """Tiene solo le CVE pubbliche che toccano un pacchetto installato.

    Con la correzione uscita, i pacchetti sono in affected_packages (si tengono
    quelli della stessa RHEL del server, '.elN'). Senza correzione l'API non li
    elenca: si usa il componente scritto all'inizio di bugzilla_description
    ("openssl: ...")."""
    installati = set(installati or [])
    out = []
    for x in cve or []:
        pk = list(x.get("affected_packages", []) or [])
        if major:
            stessi = [p for p in pk if (".el%s" % major) in p]
            pk = stessi
        nomi = set(_nome_pacchetto(p) for p in pk)
        nomi |= set(x.get("pacchetti", []) or [])
        if not x.get("affected_packages"):
            desc = x.get("bugzilla_description") or ""
            if ":" in desc:
                nomi.add(desc.split(":", 1)[0].strip())
        tocca = sorted(nomi & installati)
        if tocca:
            y = dict(x)
            y["pacchetti_installati"] = tocca
            out.append(y)
    return out


def _pm(major):
    return "yum" if major == 7 else "dnf"


def _si_no(v):
    """Ansible puo' passare i vero/falso come testo: li rimette a posto."""
    if isinstance(v, str):
        t = v.strip().lower()
        if t in ("true", "yes", "1"):
            return True
        if t in ("false", "no", "0"):
            return False
        return None
    return v


def _numero(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _normalizza(host):
    h = dict(host or {})
    for k in ("fips", "dischi_cifrati", "registrato", "virtuale", "uefi"):
        if k in h:
            h[k] = _si_no(h[k])
    for k in ("var_libero_mb", "boot_libero_mb", "kernel_installati"):
        if k in h:
            h[k] = _numero(h[k])
    for k in ("leapp_report", "paths_host"):
        v = h.get(k)
        if isinstance(v, str) and v.strip() in ("", "None", "null"):
            v = None
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                h.setdefault("_illeggibili", []).append(k)
                v = None
        h[k] = v if isinstance(v, dict) else None
    return h


def consiglia(host, paths_main, paths_rhel7, cve_pubbliche=None, precedente=None,
              major_obiettivo=None, flavour="default"):
    """Costruisce la procedura consigliata per un server.

    Se sul server c'e' gia' Leapp, il suo elenco dei salti (host["paths_host"])
    vale per il primo salto: e' quello che il programma installato sa fare.
    L'elenco pubblico su GitHub puo' citare versioni non ancora uscite, quindi
    senza Leapp installato non si mette --target e decide Leapp."""
    host = _normalizza(host)
    cve_pubbliche = cve_pubbliche or {}
    distro = host.get("distribuzione", "")
    versione = str(host.get("versione", ""))
    major = _major(versione) if versione else 0
    pm = _pm(major)

    esito = {
        "host": host.get("nome"),
        "sistema": "%s %s" % (distro, versione),
        "avvisi": [],
        "prima": [],
        "salti": [],
        "dopo": [],
        "sicurezza": {},
        "novita": [],
        "fonti": host.get("fonti", {}),
        "macchina": {k: host.get(k) for k in ("architettura", "virtuale", "tipo_virtuale", "uefi",
                                              "var_libero_mb", "boot_libero_mb", "kernel_installati",
                                              "fips", "dischi_cifrati", "registrato")},
    }

    if distro not in ("RedHat",):
        esito["avvisi"].append(
            "Il sistema e' %s: questo ruolo consiglia solo per Red Hat Enterprise Linux." % distro)
        return esito

    paths_host = host.get("paths_host")
    salti = catena(versione, paths_main, paths_rhel7, major_obiettivo, flavour)
    if salti and paths_host:
        primo = scegli_salto(versione, paths_host, paths_host, flavour)
        if primo:
            salti = [primo] + catena(primo["arrivo"], paths_main, paths_rhel7, major_obiettivo, flavour)
    if not salti:
        esito["avvisi"].append(
            "Nessun salto supportato da RHEL %s nelle linee guida pubblicate." % versione)

    # --- Sicurezza: avvisi in sospeso sul server e CVE pubbliche recenti.
    sospesi = _avvisi_sicurezza(host.get("updateinfo", []))
    gravi = [a for a in sospesi if a["gravita"] in ("critical", "important")]
    pubbliche = cve_pubbliche.get(str(major), [])
    del_server = cve_del_server(pubbliche, host.get("pacchetti"), major)
    esito["sicurezza"] = {
        "avvisi_in_sospeso": sospesi,
        "gravi_in_sospeso": gravi,
        "cve_pubbliche_guardate": len(pubbliche),
        "cve_che_toccano_il_server": del_server,
    }
    if precedente:
        viste = set(c.get("CVE") for c in (precedente.get("sicurezza", {}) or {}).get("cve_che_toccano_il_server", []))
        esito["novita"] = [c for c in del_server if c.get("CVE") not in viste]

    # --- Passi prima dell'upgrade.
    prima = esito["prima"]
    prima.append({
        "titolo": "Fai un backup o uno snapshot della macchina",
        "perche": "Leapp non ha un tasto per tornare indietro: senza copia non si torna alla versione di prima.",
        "comandi": [],
    })
    if gravi:
        prima.append({
            "titolo": "Applica prima gli aggiornamenti di sicurezza gravi (%d)" % len(gravi),
            "perche": "Ci sono avvisi critici o importanti non installati: "
                      + ", ".join(sorted(set(a["avviso"] for a in gravi))[:10]),
            "comandi": ["%s update --security -y" % pm, "reboot"],
        })
    senza_correzione = [x for x in del_server if not x.get("advisories")]
    if senza_correzione:
        esito["avvisi"].append(
            "%d falle pubbliche toccano pacchetti di questo server e Red Hat non ha ancora la "
            "correzione (%s): rilancia il ruolo nei prossimi giorni prima di procedere."
            % (len(senza_correzione), ", ".join(x["CVE"] for x in senza_correzione[:5])))
    if salti and salti[0]["serve_aggiornare_minor"]:
        prima.append({
            "titolo": "Porta il sistema alla RHEL %s" % salti[0]["parti_da"],
            "perche": "Leapp parte solo da RHEL %s; il sistema e' alla %s." % (
                salti[0]["parti_da"], versione),
            "comandi": ["%s update -y" % pm, "reboot"],
        })
    if (host.get("kernel_installati") or 0) > 2:
        prima.append({
            "titolo": "Togli i kernel vecchi",
            "perche": "Ci sono %d kernel installati: occupano /boot." % host["kernel_installati"],
            "comandi": ["package-cleanup -y --oldkernels --count=1"] if major == 7
                       else ["dnf remove --oldinstallonly -y"],
        })
    boot = host.get("boot_libero_mb")
    if boot is not None and boot < MIN_BOOT_MB:
        prima.append({
            "titolo": "Libera spazio in /boot",
            "perche": "Ci sono solo %d MB liberi; Leapp aggiunge un kernel e un initramfs." % boot,
            "comandi": [],
        })
    var = host.get("var_libero_mb")
    if var is not None and var < MIN_VAR_MB:
        prima.append({
            "titolo": "Libera spazio in /var",
            "perche": "Ci sono %d MB liberi; Leapp scarica i pacchetti nuovi in /var/lib/leapp." % var,
            "comandi": [],
        })
    for k in host.get("_illeggibili", []):
        esito["avvisi"].append(
            "Sul server il file %s di Leapp non si legge (JSON rovinato): e' stato ignorato." % (
                "/var/log/leapp/leapp-report.json" if k == "leapp_report" else "upgrade_paths.json"))
    if host.get("fips"):
        esito["avvisi"].append("Il server e' in modalita' FIPS: controlla nella guida ufficiale i limiti per questo salto.")
    if host.get("dischi_cifrati"):
        esito["avvisi"].append("Ci sono dischi cifrati LUKS: controlla nella guida ufficiale come Leapp li gestisce per questo salto.")

    registrato = host.get("registrato")
    offline = registrato is False

    # --- I salti, uno per uno.
    for i, s in enumerate(salti):
        da_major = _major(s["parti_da"])
        installa = []
        if da_major == 7:
            if offline:
                installa.append("yum install -y leapp-upgrade  # dal repository locale con i pacchetti di Leapp")
            else:
                installa += ["subscription-manager repos --enable rhel-7-server-extras-rpms",
                             "yum install -y leapp-upgrade"]
        else:
            installa.append("dnf install -y leapp-upgrade")
        opz = " --no-rhsm" if offline else ""
        # L'elenco di RHEL 7 e' archiviato e definitivo: li' la destinazione e' certa.
        sicuro = i == 0 and (bool(paths_host) or (da_major == 7 and len(s["possibili"]) == 1))
        tgt = (" --target %s" % s["arrivo"]) if sicuro else ""
        if i == 0:
            arrivo_txt = s["arrivo"] if sicuro else "%s (o la predefinita di Leapp)" % " / ".join(s["possibili"])
            titolo = "Da RHEL %s a RHEL %s" % (s["parti_da"], arrivo_txt)
        else:
            titolo = "Da RHEL %d a RHEL %d" % (da_major, _major(s["arrivo"]))
        passo = {
            "titolo": titolo,
            "arrivo": s["arrivo"] if sicuro else None,
            "guida": DOCS.get(da_major),
            "altre_destinazioni": [v for v in s["possibili"] if v != s["arrivo"]],
            "comandi": installa + [
                "leapp preupgrade%s%s" % (tgt, opz),
                "less /var/log/leapp/leapp-report.txt  # leggi il rapporto e risolvi i blocchi",
                "leapp upgrade%s%s" % (tgt, opz),
                "reboot",
                "cat /etc/redhat-release; uname -r  # controlla la versione di arrivo",
            ],
            "note": [],
        }
        if i > 0:
            passo["comandi"] = ["%s update -y; reboot  # parti dall'ultima minor della RHEL %d" % (_pm(da_major), da_major)] + passo["comandi"]
            passo["note"].append(
                "La versione esatta a cui arrivi col salto precedente si sa solo dopo: "
                "rilancia questo ruolo dopo quel salto e avrai i comandi precisi per questo.")
        elif not sicuro:
            passo["note"].append(
                "Senza --target Leapp sceglie la destinazione predefinita della versione installata. "
                "Per sceglierla tu: dopo aver installato leapp-upgrade rilancia questo ruolo, "
                "che leggera' l'elenco del programma installato.")
        if offline:
            passo["note"].append(
                "Server non registrato: prepara i repository della versione di arrivo in "
                "/etc/leapp/files/leapp_upgrade_repositories.repo (per esempio dal DVD "
                "servito via http, come nei playbook InstallEnv2Leapp).")
        if i == 0:
            passo["blocchi_attuali"] = _blocchi_leapp(host.get("leapp_report"))
        esito["salti"].append(passo)

    # --- Passi finali.
    if salti:
        fine = salti[-1]["arrivo"]
        vecchio = ".el%d" % major
        esito["dopo"] = [
            {"titolo": "Controlla i pacchetti rimasti della versione vecchia",
             "comandi": ["rpm -qa | grep -e '\\.el[%s]' | sort" % "".join(str(m) for m in range(major, _major(fine)))],
             "perche": "Pacchetti %s rimasti vanno aggiornati o tolti a mano." % vecchio},
            {"titolo": "Togli Leapp e i suoi residui",
             "comandi": ["dnf remove -y $(rpm -qa | grep -e leapp -e snactor)",
                         "sed -i '/^exclude=/d' /etc/dnf/dnf.conf  # solo se contiene i pacchetti di Leapp",
                         "rm -rf /var/lib/leapp /var/log/leapp /root/tmp_leapp_py3"],
             "perche": "Leapp lascia i suoi pacchetti esclusi dagli aggiornamenti in dnf.conf."},
            {"titolo": "Togli i kernel vecchi",
             "comandi": ["dnf remove --oldinstallonly -y"],
             "perche": "Restano i kernel della versione precedente."},
            {"titolo": "Applica gli aggiornamenti della RHEL %d" % _major(fine),
             "comandi": ["dnf update -y", "reboot"],
             "perche": "Chiude le falle uscite dopo la versione di arrivo."},
        ]

    # --- Cosa e' cambiato rispetto al giro precedente.
    if precedente:
        def impronta(e):
            return [[p.get("titolo"), p.get("comandi")] for p in
                    (e.get("prima", []) or []) + (e.get("salti", []) or []) + (e.get("dopo", []) or [])]
        esito["procedura_cambiata"] = impronta(precedente) != impronta(esito)
    else:
        esito["procedura_cambiata"] = False
    return esito


class FilterModule(object):
    def filters(self):
        return {"consiglia_upgrade": consiglia, "cve_del_server": cve_del_server}
