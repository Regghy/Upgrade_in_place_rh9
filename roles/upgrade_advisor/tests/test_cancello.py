# -*- coding: utf-8 -*-
"""Prove del cancello (si parte solo se e' tutto a posto) e dei criteri aziendali."""
import json
import os
import sys
import unittest

QUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(QUI, "..", "filter_plugins"))
import consiglia as c  # noqa: E402

FILES = os.path.join(QUI, "..", "files")
MAIN = json.load(open(os.path.join(FILES, "upgrade_paths_main.json")))
RH7 = json.load(open(os.path.join(FILES, "upgrade_paths_rhel7.json")))
SUL_SERVER = {"rhel": {"default": {"8.10": ["9.6"], "8": ["9.6"]}}}
REPORT_PULITO = {"entries": [{"title": "Solo informazioni", "groups": ["info"]}]}


def pronto(**kw):
    """Un server RHEL 8.10 virtuale con tutto a posto."""
    base = {"nome": "web01", "distribuzione": "RedHat", "versione": "8.10",
            "architettura": "x86_64", "virtuale": True, "registrato": True,
            "ram_mb": 4096, "var_libero_mb": 20000, "boot_libero_mb": 500,
            "kernel_installati": 2, "updateinfo": [], "pacchetti": ["bash", "openssl"],
            "leapp_installato": True, "leapp_report": REPORT_PULITO, "report_eta_ore": 1,
            "paths_host": SUL_SERVER}
    base.update(kw)
    return base


def esito(host, file_criteri=None, gruppi=None, extra=None, obiettivo=9, cve=None):
    crit = c.criteri_host(file_criteri or {}, host["nome"], gruppi, extra)
    return c.consiglia(host, MAIN, RH7, cve, None, obiettivo, "default", crit)


def codici(e):
    return [b["codice"] for b in e["blocchi"]]


class ViaLibera(unittest.TestCase):
    def test_tutto_a_posto(self):
        e = esito(pronto())
        self.assertEqual(e["blocchi"], [])
        self.assertEqual(e["stato"], "via_libera")
        self.assertEqual(e["prossimo_comando"], "leapp upgrade --target 9.6")

    def test_gia_aggiornato(self):
        e = esito(pronto(versione="9.6"), obiettivo=9)
        self.assertEqual(e["stato"], "aggiornato")
        self.assertEqual(e["blocchi"], [])


class Blocchi(unittest.TestCase):
    def test_macchina_fisica_con_poca_memoria(self):
        e = esito(pronto(virtuale=False, ram_mb=1024), extra={"backup_confermato": True})
        self.assertEqual(e["stato"], "bloccato")
        b = e["blocchi"][0]
        self.assertEqual(b["codice"], "UA-RAM")
        self.assertEqual(b["trovato"], "1024 MiB")
        self.assertEqual(b["richiesto"], "almeno 1536 MiB")
        self.assertIn("Minimum memory requirements", b["fonte"])

    def test_power_vuole_3_gb(self):
        e = esito(pronto(architettura="ppc64le", ram_mb=2048))
        self.assertIn("almeno 3072 MiB", [b["richiesto"] for b in e["blocchi"]])

    def test_memoria_sconosciuta_blocca(self):
        e = esito(pronto(ram_mb=None))
        self.assertIn("UA-RAM", codici(e))

    def test_spazio(self):
        e = esito(pronto(boot_libero_mb=60, var_libero_mb=None))
        spazio = [b for b in e["blocchi"] if b["codice"] == "UA-SPAZIO"]
        self.assertEqual(len(spazio), 2)
        self.assertIn("/boot", spazio[0]["problema"])
        self.assertEqual(spazio[0]["trovato"], "60 MiB liberi")
        self.assertIn("sconosciuto", spazio[1]["trovato"])

    def test_fips_da_7(self):
        e = esito(pronto(versione="7.9", fips=True, paths_host=None), obiettivo=8)
        self.assertIn("UA-FIPS", codici(e))

    def test_fips_da_8_non_blocca(self):
        e = esito(pronto(fips=True))
        self.assertNotIn("UA-FIPS", codici(e))

    def test_luks(self):
        luks = [{"dispositivo": "/dev/sda3", "versione": "1", "tpm2": False},
                {"dispositivo": "/dev/sdb1", "versione": "2", "tpm2": True}]
        e = esito(pronto(luks=luks))
        b = [x for x in e["blocchi"] if x["codice"] == "UA-LUKS"][0]
        self.assertIn("/dev/sda3", b["trovato"])
        self.assertNotIn("/dev/sdb1", b["trovato"])

    def test_minor_vecchia(self):
        e = esito(pronto(versione="8.6", paths_host=None))
        self.assertIn("UA-MINOR", codici(e))

    def test_senza_registrazione_e_senza_repository(self):
        self.assertIn("UA-REPO", codici(esito(pronto(registrato=False))))
        self.assertNotIn("UA-REPO", codici(esito(pronto(registrato=False, repo_locale=True))))

    def test_senza_leapp(self):
        e = esito(pronto(leapp_installato=False, leapp_report=None, paths_host=None))
        self.assertIn("UA-LEAPP", codici(e))
        self.assertIsNone(e["salti"][0]["arrivo"])

    def test_preupgrade_mancante_o_vecchio(self):
        self.assertIn("UA-PREUPGRADE", codici(esito(pronto(leapp_report=None))))
        self.assertIn("UA-PREUPGRADE", codici(esito(pronto(report_eta_ore=50))))
        self.assertNotIn("UA-PREUPGRADE", codici(esito(pronto(report_eta_ore=50),
                                                       {"generale": {"ore_validita_preupgrade": 72}})))

    def test_blocchi_ed_errori_di_leapp_con_testo_esatto(self):
        rep = {"entries": [
            {"title": "Missing required answers in the answer file", "summary": "check_vdo",
             "groups": ["inhibitor"],
             "detail": {"remediations": [{"type": "command",
                                          "context": ["leapp", "answer", "--section", "check_vdo.confirm=True"]}]}},
            {"title": "Actor x failed", "summary": "Traceback", "groups": ["error"]}]}
        e = esito(pronto(leapp_report=rep))
        self.assertEqual(codici(e), ["UA-LEAPP-BLOCCO", "UA-LEAPP-ERRORE"])
        self.assertIn("Missing required answers", e["blocchi"][0]["problema"])
        self.assertEqual(e["blocchi"][0]["rimedio"], "leapp answer --section check_vdo.confirm=True")

    def test_backup_obbligatorio_per_le_fisiche(self):
        self.assertIn("UA-BACKUP", codici(esito(pronto(virtuale=False))))
        self.assertNotIn("UA-BACKUP", codici(esito(pronto(virtuale=False), extra={"backup_confermato": True})))
        self.assertNotIn("UA-BACKUP", codici(esito(pronto())))

    def test_sistema_non_redhat(self):
        e = esito(pronto(distribuzione="CentOS"))
        self.assertEqual(codici(e), ["UA-SISTEMA"])
        self.assertEqual(e["stato"], "bloccato")


class CriteriAziendali(unittest.TestCase):
    FILE = {
        "generale": {"var_minimo_mb": 8000, "pacchetti_vietati": ["agente-vecchio"],
                     "controlli": [{"nome": "Oracle spento", "comando": "pgrep -f ora_pmon",
                                    "ok_se": "rc_diverso_da_zero",
                                    "errore": "Il database Oracle e' acceso: va fermato prima dell'upgrade"}]},
        "gruppi": {"web": {"obiettivo": 8}, "fisici": {"ram_minima_mb": 8192}},
        "server": {"db-*": {"backup_confermato": True}},
        "escludi": ["sap-*", {"server": "legacy01", "motivo": "applicazione certificata solo su RHEL 8"}],
        "escludi_gruppi": [{"gruppo": "cluster", "motivo": "i cluster si aggiornano a mano"}],
    }

    def test_esclusioni_con_motivo(self):
        self.assertEqual(esito(pronto(nome="sap-01"), self.FILE)["stato"], "escluso")
        e = esito(pronto(nome="legacy01"), self.FILE)
        self.assertIn("certificata", e["avvisi"][0])
        e = esito(pronto(nome="nodo1"), self.FILE, gruppi=["cluster"])
        self.assertEqual(e["stato"], "escluso")
        self.assertIn("a mano", e["avvisi"][0])

    def test_criteri_per_gruppo_e_per_server(self):
        crit = c.criteri_host(self.FILE, "db-02", ["fisici"])
        self.assertEqual(crit["ram_minima_mb"], 8192)
        self.assertTrue(crit["backup_confermato"])
        self.assertEqual(crit["var_minimo_mb"], 8000)

    def test_obiettivo_del_gruppo(self):
        e = esito(pronto(versione="8.10"), self.FILE, gruppi=["web"], obiettivo=10,
                  extra=None)
        self.assertEqual(e["stato"], "aggiornato")

    def test_ram_aziendale_piu_alta(self):
        e = esito(pronto(nome="db-02", virtuale=False, ram_mb=4096,
                         controlli_aziendali=[{"nome": "Oracle spento", "rc": 1, "uscita": ""}]),
                  self.FILE, gruppi=["fisici"])
        b = [x for x in e["blocchi"] if x["codice"] == "UA-RAM"][0]
        self.assertEqual(b["richiesto"], "almeno 8192 MiB")
        self.assertIn("ram_minima_mb", b["fonte"])

    def test_pacchetto_vietato_e_spazio_aziendale(self):
        e = esito(pronto(pacchetti=["bash", "agente-vecchio"], var_libero_mb=6000,
                         controlli_aziendali=[{"nome": "Oracle spento", "rc": 1, "uscita": ""}]), self.FILE)
        self.assertEqual(sorted(codici(e)), ["UA-PACCHETTO", "UA-SPAZIO"])

    def test_controllo_aziendale(self):
        acceso = [{"nome": "Oracle spento", "rc": 0, "uscita": "4242"}]
        e = esito(pronto(controlli_aziendali=acceso), self.FILE)
        b = [x for x in e["blocchi"] if x["codice"] == "UA-AZIENDA-1"][0]
        self.assertEqual(b["problema"], "Il database Oracle e' acceso: va fermato prima dell'upgrade")
        self.assertIn("4242", b["trovato"])
        spento = [{"nome": "Oracle spento", "rc": 1, "uscita": ""}]
        self.assertNotIn("UA-AZIENDA-1", codici(esito(pronto(controlli_aziendali=spento), self.FILE)))

    def test_controllo_non_eseguito_blocca(self):
        self.assertIn("UA-AZIENDA-1", codici(esito(pronto(), self.FILE)))

    def test_controllo_solo_avviso(self):
        f = {"generale": {"controlli": [{"nome": "x", "comando": "false", "blocca": False}]}}
        e = esito(pronto(controlli_aziendali=[{"nome": "x", "rc": 1, "uscita": ""}]), f)
        self.assertEqual(e["stato"], "via_libera")
        self.assertTrue(any("UA-AZIENDA-1" in a for a in e["avvisi"]))

    def test_sicurezza_bloccante_se_richiesto(self):
        righe = ["RHSA-2026:1234 Important/Sec.  openssl-1:3.0.7-28.el8.x86_64"]
        self.assertEqual(esito(pronto(updateinfo=righe))["stato"], "via_libera")
        e = esito(pronto(updateinfo=righe), {"generale": {"blocca_aggiornamenti_gravi": True}})
        self.assertIn("UA-SICUREZZA", codici(e))

    def test_testi_da_ansible(self):
        e = esito(pronto(virtuale="False", ram_mb="1000"), extra={"backup_confermato": "true"})
        self.assertEqual(codici(e), ["UA-RAM"])


if __name__ == "__main__":
    unittest.main()
