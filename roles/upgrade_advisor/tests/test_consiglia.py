# -*- coding: utf-8 -*-
"""Prove della logica dei consigli: python -m unittest discover -s tests"""
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


def host(**kw):
    base = {"nome": "srv1", "distribuzione": "RedHat", "versione": "8.10",
            "registrato": True, "var_libero_mb": 20000, "boot_libero_mb": 500,
            "kernel_installati": 2, "updateinfo": []}
    base.update(kw)
    return base


class Salti(unittest.TestCase):
    def test_rhel7_tutta_la_catena(self):
        salti = c.catena("7.6", MAIN, RH7)
        self.assertEqual([s["parti_da"] for s in salti], ["7.9", "8.10", salti[2]["parti_da"]])
        self.assertTrue(salti[0]["serve_aggiornare_minor"])
        self.assertEqual(salti[0]["arrivo"], "8.10")
        self.assertEqual(c._major(salti[-1]["arrivo"]), 10)

    def test_obiettivo_si_ferma(self):
        salti = c.catena("7.9", MAIN, RH7, major_obiettivo=8)
        self.assertEqual(len(salti), 1)
        self.assertEqual(salti[0]["arrivo"], "8.10")

    def test_rhel8_vecchia_deve_salire_alla_810(self):
        s = c.scegli_salto("8.6", MAIN, RH7)
        self.assertEqual(s["parti_da"], "8.10")
        self.assertTrue(s["serve_aggiornare_minor"])

    def test_rhel10_niente_da_fare(self):
        esito = c.consiglia(host(versione="10.1"), MAIN, RH7)
        self.assertEqual(esito["salti"], [])
        self.assertTrue(any("Nessun salto" in a for a in esito["avvisi"]))

    def test_non_redhat(self):
        esito = c.consiglia(host(distribuzione="Rocky"), MAIN, RH7)
        self.assertEqual(esito["salti"], [])
        self.assertIn("Rocky", esito["avvisi"][0])


class Procedura(unittest.TestCase):
    def test_senza_leapp_nessun_target(self):
        esito = c.consiglia(host(), MAIN, RH7, major_obiettivo=9)
        cmd = esito["salti"][0]["comandi"]
        self.assertIn("leapp preupgrade", cmd)
        self.assertIn("leapp upgrade", cmd)
        self.assertFalse(any("--target" in x for x in cmd))

    def test_con_leapp_installato_usa_il_suo_elenco(self):
        sul_server = {"rhel": {"default": {"8.10": ["9.6"], "8": ["9.6"]}}}
        esito = c.consiglia(host(paths_host=sul_server), MAIN, RH7)
        cmd = esito["salti"][0]["comandi"]
        self.assertIn("leapp upgrade --target 9.6", cmd)
        # il salto dopo: da 9 a 10, da rilanciare dopo il primo
        self.assertEqual(len(esito["salti"]), 2)
        self.assertEqual(esito["salti"][1]["titolo"], "Da RHEL 9 a RHEL 10")
        self.assertTrue(esito["salti"][1]["comandi"][0].startswith("dnf update -y"))
        self.assertTrue(any("rilancia" in n for n in esito["salti"][1]["note"]))

    def test_server_non_registrato(self):
        esito = c.consiglia(host(registrato=False, versione="7.9"), MAIN, RH7, major_obiettivo=8)
        cmd = esito["salti"][0]["comandi"]
        self.assertTrue(all("--no-rhsm" in x for x in cmd if x.startswith("leapp ")))
        self.assertFalse(any("subscription-manager" in x for x in cmd))
        self.assertTrue(esito["salti"][0]["note"])

    def test_spazio_kernel_fips(self):
        esito = c.consiglia(host(var_libero_mb=1000, boot_libero_mb=50,
                                 kernel_installati=4, fips=True), MAIN, RH7)
        titoli = [p["titolo"] for p in esito["prima"]]
        self.assertIn("Libera spazio in /var", titoli)
        self.assertIn("Libera spazio in /boot", titoli)
        self.assertIn("Togli i kernel vecchi", titoli)
        self.assertTrue(any("FIPS" in a for a in esito["avvisi"]))

    def test_blocchi_del_report(self):
        report = {"entries": [
            {"title": "Moduli vietati", "summary": "pata_acpi", "groups": ["inhibitor"],
             "detail": {"remediations": [{"type": "command", "context": ["rmmod", "pata_acpi"]}]}},
            {"title": "Solo un'informazione", "groups": ["info"]},
        ]}
        esito = c.consiglia(host(leapp_report=report), MAIN, RH7)
        blocchi = esito["salti"][0]["blocchi_attuali"]
        self.assertEqual(len(blocchi), 1)
        self.assertEqual(blocchi[0]["rimedi"][0]["testo"], "rmmod pata_acpi")


class DatiDaAnsible(unittest.TestCase):
    def test_testi_al_posto_di_vero_falso_e_json(self):
        rep = json.dumps({"entries": [{"title": "X", "groups": ["inhibitor"]}]})
        esito = c.consiglia(host(registrato="False", kernel_installati="4", leapp_report=rep), MAIN, RH7)
        self.assertTrue(any("--no-rhsm" in x for x in esito["salti"][0]["comandi"]))
        self.assertEqual(esito["salti"][0]["blocchi_attuali"][0]["titolo"], "X")
        self.assertIn("Togli i kernel vecchi", [p["titolo"] for p in esito["prima"]])

    def test_file_mancante_come_testo_vuoto(self):
        esito = c.consiglia(host(paths_host="", leapp_report="None"), MAIN, RH7)
        self.assertFalse(any("non si legge" in a for a in esito["avvisi"]))

    def test_rhel7_destinazione_certa(self):
        esito = c.consiglia(host(versione="7.9"), MAIN, RH7)
        self.assertIn("leapp upgrade --target 8.10", esito["salti"][0]["comandi"])

    def test_json_rovinato(self):
        esito = c.consiglia(host(paths_host="{rhel:", leapp_report="{x"), MAIN, RH7)
        self.assertEqual(sum("non si legge" in a for a in esito["avvisi"]), 2)
        self.assertTrue(esito["salti"])


class Sicurezza(unittest.TestCase):
    RIGHE = [
        "RHSA-2026:1234 Important/Sec.  openssl-1:3.0.7-28.el9_4.x86_64",
        "RHSA-2026:1300 Moderate/Sec.   curl-7.76.1-29.el9_4.x86_64",
        "RHBA-2026:1 bugfix pippo",
    ]

    def test_aggiornamenti_gravi_prima(self):
        esito = c.consiglia(host(versione="9.4", updateinfo=self.RIGHE), MAIN, RH7)
        s = esito["sicurezza"]
        self.assertEqual(len(s["avvisi_in_sospeso"]), 2)
        self.assertEqual([a["avviso"] for a in s["gravi_in_sospeso"]], ["RHSA-2026:1234"])
        primo_passo = [p for p in esito["prima"] if "sicurezza" in p["titolo"]]
        self.assertEqual(primo_passo[0]["comandi"][0], "dnf update --security -y")

    CVE = {"9": [
        {"CVE": "CVE-1", "affected_packages": ["openssl-1:3.0.7-28.el9_4"], "advisories": ["RHSA-2026:1"]},
        {"CVE": "CVE-2", "affected_packages": ["openssl-1:3.0.7-29.el9_4"], "advisories": []},
        {"CVE": "CVE-3", "affected_packages": ["nginx-1:1.20.1-16.el9_4"], "advisories": ["RHSA-2026:3"]},
        {"CVE": "CVE-4", "affected_packages": ["bash-0:5.2-1.el10_1"], "advisories": ["RHSA-2026:4"]},
        {"CVE": "CVE-5", "affected_packages": [], "advisories": [], "bugzilla_description": "bash: falla nuova"},
    ]}

    def test_solo_le_cve_dei_pacchetti_installati(self):
        esito = c.consiglia(host(versione="9.4", pacchetti=["openssl", "bash"]), MAIN, RH7, cve_pubbliche=self.CVE)
        tocca = esito["sicurezza"]["cve_che_toccano_il_server"]
        # CVE-4 e' corretta solo per RHEL 10; CVE-5 non ha ancora correzione
        self.assertEqual([x["CVE"] for x in tocca], ["CVE-1", "CVE-2", "CVE-5"])
        self.assertEqual(tocca[0]["pacchetti_installati"], ["openssl"])
        self.assertTrue(any("CVE-2" in a for a in esito["avvisi"]))

    def test_novita_rispetto_al_giro_prima(self):
        prec = {"sicurezza": {"cve_che_toccano_il_server": [{"CVE": "CVE-1"}]}}
        esito = c.consiglia(host(versione="9.4", pacchetti=["openssl"]), MAIN, RH7,
                            cve_pubbliche=self.CVE, precedente=prec)
        self.assertEqual([x["CVE"] for x in esito["novita"]], ["CVE-2"])  # bash non installato

    def test_rhel7_usa_yum(self):
        esito = c.consiglia(host(versione="7.9", updateinfo=self.RIGHE[:1]), MAIN, RH7)
        passo = [p for p in esito["prima"] if "sicurezza" in p["titolo"]][0]
        self.assertEqual(passo["comandi"][0], "yum update --security -y")


if __name__ == "__main__":
    unittest.main()
