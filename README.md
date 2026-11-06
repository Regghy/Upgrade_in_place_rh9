# Upgrade in place di RHEL con Leapp

Due cose in questo progetto:

1. **`consiglia_upgrade.yml`** e il ruolo **`upgrade_advisor`**: guardano ogni server e scrivono la procedura esatta per aggiornarlo sul posto (RHEL 7 → 8 → 9 → 10). Ad ogni giro si aggiornano da soli sulle linee guida pubbliche di Red Hat e sulle falle di sicurezza (CVE) appena uscite. **Non cambiano niente sui server**: leggono soltanto.
2. I playbook che preparano ed eseguono l'upgrade (`InstallEnv2Leapp*.yaml`, `LeappPreupgrade.yaml`, `Post*.yaml`), per server fisici e macchine virtuali senza accesso a Internet.

## Il consigliere: come si usa

```bash
ansible-playbook -i inventario consiglia_upgrade.yml
```

Per fermarsi a una versione (per esempio RHEL 9):

```bash
ansible-playbook -i inventario consiglia_upgrade.yml -e upgrade_advisor_obiettivo=9
```

Si può lanciare anche con `--check`: i rapporti vengono scritti comunque.

Il risultato finisce nella cartella `rapporti/`:

- `RIEPILOGO.md`: una riga per server, con i salti da fare, se la procedura è cambiata e le falle nuove;
- `<server>.md`: la procedura passo per passo, con i comandi da copiare;
- `<server>.json`: gli stessi dati, per altri programmi; serve anche al giro dopo, per capire cosa è cambiato.

Un esempio vero, preso dalla prova su RHEL 8.10: [esempi/rapporto-rhel8.md](esempi/rapporto-rhel8.md).

### Cosa guarda sul server

Versione e architettura, macchina virtuale o fisica, avvio UEFI o BIOS, spazio libero in `/var` e `/boot`, numero di kernel installati, FIPS, dischi cifrati LUKS, registrazione con Red Hat, aggiornamenti di sicurezza non ancora installati (`dnf updateinfo`), il rapporto dell'ultimo `leapp preupgrade` (con i blocchi e i comandi per toglierli) e, se c'è, l'elenco dei salti del Leapp installato.

### Da dove prende le regole

- **Salti di versione supportati**: il file `upgrade_paths.json` del progetto di Red Hat [oamg/leapp-repository](https://github.com/oamg/leapp-repository), scaricato a ogni giro; per RHEL 7 si usa il ramo archiviato `rhel-7-archived`. Senza Internet si usano le copie in `roles/upgrade_advisor/files/`.
- **Falle di sicurezza**: la [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/cve.json), con le falle critiche e importanti degli ultimi 30 giorni. Si tengono solo quelle che toccano pacchetti installati sul server. Senza Internet si usa la copia del giro precedente (`rapporti/_cve.json`).

L'elenco pubblico su GitHub può citare versioni non ancora uscite. Per questo il comando `--target` si scrive solo quando la destinazione è certa: quando l'elenco viene dal Leapp installato sul server, oppure da RHEL 7, il cui elenco è chiuso. Negli altri casi Leapp sceglie la sua destinazione predefinita. Dopo ogni salto conviene rilanciare il consigliere, che calcolerà i comandi precisi per il salto successivo.

### Come cambia la procedura con le falle

- Se sul server mancano aggiornamenti di sicurezza critici o importanti, il primo passo diventa installarli.
- Se una falla nuova tocca un pacchetto del server e Red Hat non ha ancora la correzione, il rapporto avvisa di aspettare.
- A ogni giro il rapporto dice se la procedura è cambiata rispetto al giro prima e quali falle sono nuove.

### Farlo girare da solo ogni giorno

Con cron, sul computer da cui si lancia Ansible:

```cron
30 6 * * * cd /percorso/Upgrade_in_place_rh9 && ansible-playbook -i inventario consiglia_upgrade.yml >> rapporti/giro.log 2>&1
```

### Versione di Ansible

- Server RHEL 9 e 10: va bene qualsiasi ansible-core recente.
- Server RHEL 8: ansible-core 2.17 e successivi non usano più il Python 3.6 di sistema. Si può installare un Python più nuovo sul server (`dnf install python3.11`, e poi `ansible_python_interpreter=/usr/bin/python3.11` nell'inventario), oppure usare ansible-core 2.16.
- Server RHEL 7: serve ansible-core 2.16, l'ultimo che lavora con Python 2.7.

### Prove

La logica dei consigli ha le sue prove, che non hanno bisogno di Ansible:

```bash
cd roles/upgrade_advisor && python3 -m unittest discover -s tests
```

Il ruolo è stato provato su container UBI 7.9, 8.10 e 9 (sono immagini, non server veri: niente kernel e niente Leapp installato).

## I playbook dell'upgrade

| File | Cosa fa |
|---|---|
| `InstallEnv2Leapp-Physical.yaml` | Server fisico RHEL 7: monta il DVD della RHEL 8, lo serve via http e installa Leapp da un repository locale |
| `InstallEnv2Leapp.yaml` | Macchina virtuale RHEL 8: lo stesso con il DVD della RHEL 9 |
| `LeappPreupgrade.yaml` | Lancia `leapp preupgrade` senza registrazione e conferma le risposte richieste |
| `PostUpgradeTasks.yaml` | Dopo l'upgrade: toglie i kernel vecchi e il repository di Leapp |
| `PostRhel9.6Tasks.yaml` | Dopo l'upgrade a RHEL 9: pulisce le esclusioni di Leapp in `dnf.conf` e i file di appoggio |
