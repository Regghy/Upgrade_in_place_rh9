# Upgrade in place di ua-rhel8

Sistema attuale: **RedHat 8.10** (x86_64,
macchina virtuale container,
avvio BIOS,
non registrato: upgrade dai repository locali).

Rapporto del 2026-11-06T15:06:26Z. Linee guida: scaricati ora da GitHub (oamg/leapp-repository). Falle: scaricate ora da Red Hat, dal 2026-10-07.


## Attenzione

- 3 falle pubbliche toccano pacchetti di questo server e Red Hat non ha ancora la correzione (CVE-2026-120194, CVE-2026-118131, CVE-2026-115506): rilancia il ruolo nei prossimi giorni prima di procedere.

## Prima dell'upgrade

1. **Fai un backup o uno snapshot della macchina**. Leapp non ha un tasto per tornare indietro: senza copia non si torna alla versione di prima.

## Salto 1: Da RHEL 8.10 a RHEL 9.6

Guida ufficiale: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/index

```bash
dnf install -y leapp-upgrade
leapp preupgrade --target 9.6 --no-rhsm
less /var/log/leapp/leapp-report.txt  # leggi il rapporto e risolvi i blocchi
leapp upgrade --target 9.6 --no-rhsm
reboot
cat /etc/redhat-release; uname -r  # controlla la versione di arrivo
```

- Server non registrato: prepara i repository della versione di arrivo in /etc/leapp/files/leapp_upgrade_repositories.repo (per esempio dal DVD servito via http, come nei playbook InstallEnv2Leapp).

**Problemi che bloccano l'upgrade, dall'ultimo `leapp preupgrade`:**

- **Missing required answers in the answer file**: One or more sections in answerfile are missing user choices
  - comando: `leapp answer --section check_vdo.confirm=True`

## Salto 2: Da RHEL 9 a RHEL 10

Guida ufficiale: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/upgrading_from_rhel_9_to_rhel_10/index

```bash
dnf update -y; reboot  # parti dall'ultima minor della RHEL 9
dnf install -y leapp-upgrade
leapp preupgrade --no-rhsm
less /var/log/leapp/leapp-report.txt  # leggi il rapporto e risolvi i blocchi
leapp upgrade --no-rhsm
reboot
cat /etc/redhat-release; uname -r  # controlla la versione di arrivo
```

- La versione esatta a cui arrivi col salto precedente si sa solo dopo: rilancia questo ruolo dopo quel salto e avrai i comandi precisi per questo.

- Server non registrato: prepara i repository della versione di arrivo in /etc/leapp/files/leapp_upgrade_repositories.repo (per esempio dal DVD servito via http, come nei playbook InstallEnv2Leapp).

## Dopo l'ultimo salto

1. **Controlla i pacchetti rimasti della versione vecchia**. Pacchetti .el8 rimasti vanno aggiornati o tolti a mano.

   ```bash
   rpm -qa | grep -e '\.el[89]' | sort
   ```
2. **Togli Leapp e i suoi residui**. Leapp lascia i suoi pacchetti esclusi dagli aggiornamenti in dnf.conf.

   ```bash
   dnf remove -y $(rpm -qa | grep -e leapp -e snactor)
   sed -i '/^exclude=/d' /etc/dnf/dnf.conf  # solo se contiene i pacchetti di Leapp
   rm -rf /var/lib/leapp /var/log/leapp /root/tmp_leapp_py3
   ```
3. **Togli i kernel vecchi**. Restano i kernel della versione precedente.

   ```bash
   dnf remove --oldinstallonly -y
   ```
4. **Applica gli aggiornamenti della RHEL 10**. Chiude le falle uscite dopo la versione di arrivo.

   ```bash
   dnf update -y
   reboot
   ```

## Sicurezza

- Aggiornamenti di sicurezza non installati: 0
  (gravi: 0).
- Falle pubbliche recenti guardate: 408;
  quelle che toccano pacchetti di questo server: 6.

| Falla | Gravita' | Pacchetti del server | Correzione |
|---|---|---|---|
| CVE-2026-114406 | critical | ca-certificates | RHSA-2026:86595, RHSA-2026:88455, RHSA-2026:88459 e altre 72 |
| CVE-2026-120194 | important | json-glib | non ancora uscita |
| CVE-2026-118131 | important | gnupg2 | non ancora uscita |
| CVE-2026-115506 | important | expat | non ancora uscita |
| CVE-2026-111497 | important | brotli | RHSA-2026:10757, RHSA-2026:10766, RHSA-2026:10767 e altre 80 |
| CVE-2026-77214 | important | expat | RHSA-2026:77959, RHSA-2026:85985, RHSA-2026:88247 e altre 6 |
