# Upgrade in place di RHEL con Leapp

Tre cose in questo progetto:

1. **`consiglia_upgrade.yml`** e il ruolo **`upgrade_advisor`**: guardano ogni server e scrivono la procedura esatta per aggiornarlo sul posto (RHEL 7 → 8 → 9 → 10), con un esito chiaro: **via libera**, **bloccato** (con l'errore esatto), **escluso** o **già aggiornato**. A ogni giro si aggiornano da soli sulle linee guida pubbliche di Red Hat e sulle falle di sicurezza (CVE) appena uscite. **Non cambiano niente sui server**: leggono soltanto.
2. **`LeappUpgrade.yaml`**: fa partire l'upgrade, ma **solo sui server con il via libera**. Gli altri si fermano con l'errore esatto e non vengono toccati.
3. I playbook che preparano l'upgrade (`InstallEnv2Leapp*.yaml`, `LeappPreupgrade.yaml`, `Post*.yaml`), per server fisici e macchine virtuali senza accesso a Internet.

## Il consigliere: come si usa

```bash
ansible-playbook -i inventario consiglia_upgrade.yml
```

Per fermarsi a una versione (per esempio RHEL 9), se nei criteri aziendali non c'è già un `obiettivo`:

```bash
ansible-playbook -i inventario consiglia_upgrade.yml -e upgrade_advisor_obiettivo=9
```

Si può lanciare anche con `--check`: i rapporti vengono scritti comunque.

Il risultato finisce nella cartella `rapporti/`:

- `RIEPILOGO.md`: una riga per server, con l'esito, i codici dei blocchi, i salti da fare, se la procedura è cambiata e le falle nuove;
- `<server>.md`: in cima l'esito e la tabella dei blocchi, poi la procedura passo per passo, con i comandi da copiare;
- `<server>.json`: gli stessi dati, per altri programmi; serve anche al giro dopo, per capire cosa è cambiato.

Un esempio vero, preso dalla prova su RHEL 8.10: [esempi/rapporto-rhel8.md](esempi/rapporto-rhel8.md).

### Cosa guarda sul server

Versione e architettura, memoria, macchina virtuale o fisica, avvio UEFI o BIOS, spazio libero in `/var` e `/boot`, numero di kernel installati, FIPS, dischi cifrati LUKS (versione e sblocco TPM2), registrazione con Red Hat o repository locali, aggiornamenti di sicurezza non ancora installati (`dnf updateinfo`), il rapporto dell'ultimo `leapp preupgrade` (con i blocchi, gli errori e i comandi per toglierli) e quanto è vecchio, l'elenco dei salti del Leapp installato e i controlli scritti dall'azienda.

### Da dove prende le regole

- **Salti di versione supportati**: il file `upgrade_paths.json` del progetto di Red Hat [oamg/leapp-repository](https://github.com/oamg/leapp-repository), scaricato a ogni giro; per RHEL 7 si usa il ramo archiviato `rhel-7-archived`. Senza Internet si usano le copie in `roles/upgrade_advisor/files/`.
- **Minimi di memoria e di spazio in `/boot`**: gli stessi dei controlli di Leapp (`checkmemory`, `checkbootavailspace`), così il blocco arriva prima di lanciare Leapp.
- **Falle di sicurezza**: la [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/cve.json), con le falle critiche e importanti degli ultimi 30 giorni. Si tengono solo quelle che toccano pacchetti installati sul server. Senza Internet si usa la copia del giro precedente (`rapporti/_cve.json`).

L'elenco pubblico su GitHub può citare versioni non ancora uscite. Per questo il comando `--target` si scrive solo quando la destinazione è certa: quando l'elenco viene dal Leapp installato sul server, oppure da RHEL 7, il cui elenco è chiuso. Negli altri casi Leapp sceglie la sua destinazione predefinita. Dopo ogni salto conviene rilanciare il consigliere, che calcolerà i comandi precisi per il salto successivo.

### Come cambia la procedura con le falle

- Se sul server mancano aggiornamenti di sicurezza critici o importanti, il primo passo diventa installarli.
- Se una falla nuova tocca un pacchetto del server e Red Hat non ha ancora la correzione, il rapporto avvisa di aspettare.
- A ogni giro il rapporto dice se la procedura è cambiata rispetto al giro prima e quali falle sono nuove.
- Con i criteri aziendali, aggiornamenti gravi mancanti e falle senza correzione possono anche bloccare l'upgrade.

## Quando l'upgrade non può partire

Il via libera arriva solo se tutti i controlli passano. Se un valore non si riesce a misurare, si blocca: senza la certezza che funzioni, l'upgrade non parte. Ogni blocco ha un codice, il valore trovato, quello richiesto, come risolverlo e da dove viene la regola. Un esempio di quello che stampa `LeappUpgrade.yaml`:

```text
UPGRADE NON AVVIATO su db-01 (RedHat 8.10).
[UA-RAM] Memoria insufficiente per RHEL 9
    trovato: 1024 MiB
    richiesto: almeno 1536 MiB
    come risolvere: Aggiungi memoria alla macchina (sulle fisiche: banchi di RAM; ...) e rilancia.
    fonte: Leapp lo blocca con: "Minimum memory requirements for the target OS are not met"
```

| Codice | Quando blocca |
|---|---|
| `UA-SISTEMA` | Il sistema non è Red Hat Enterprise Linux |
| `UA-VERSIONE` | Dalla versione attuale non c'è un upgrade supportato |
| `UA-ARCH` | Architettura non fra quelle ammesse |
| `UA-RAM` | Memoria sotto il minimo di Leapp (1536 MiB, 3072 su Power) o sotto quello aziendale; anche se non si riesce a leggerla |
| `UA-SPAZIO` | Poco spazio libero in `/boot` (Leapp vuole 100 MiB) o in `/var`; anche se non si riesce a misurarlo |
| `UA-FIPS` | FIPS acceso su RHEL 7: Leapp non fa il salto a RHEL 8 |
| `UA-LUKS` | Dischi cifrati che non sono LUKS2 con sblocco Clevis TPM2 |
| `UA-MINOR` | Il sistema non è all'ultima minor da cui parte Leapp (per esempio 8.6 invece di 8.10) |
| `UA-REPO` | Né registrato con Red Hat né con i repository locali in `/etc/leapp/files/leapp_upgrade_repositories.repo` |
| `UA-LEAPP` | Leapp non è installato |
| `UA-PREUPGRADE` | Manca un `leapp preupgrade`, oppure è più vecchio delle ore permesse (24 di base) |
| `UA-LEAPP-BLOCCO`, `UA-LEAPP-ERRORE` | Il `leapp preupgrade` ha trovato un blocco o un errore: si riportano il titolo e il testo di Leapp e il comando per risolverlo |
| `UA-BACKUP` | Backup non confermato, dove i criteri lo chiedono (di base sulle macchine fisiche) |
| `UA-PACCHETTO` | È installato un pacchetto vietato dai criteri aziendali |
| `UA-SICUREZZA`, `UA-FALLA` | Aggiornamenti gravi mancanti o falle senza correzione, solo se i criteri lo chiedono |
| `UA-AZIENDA-n` o codice scelto | Un controllo aziendale non è passato, o non è stato eseguito |

Altri due codici escono durante l'upgrade vero: `UA-UPGRADE` se `leapp upgrade` si ferma (il server non viene riavviato), `UA-ARRIVO` se dopo il riavvio la versione non è quella attesa.

## Criteri aziendali ed esclusioni

Il tecnico scrive le regole dell'azienda in `criteri_aziendali.yml`, nella cartella del progetto. Si parte copiando l'esempio commentato [esempi/criteri_aziendali.yml](esempi/criteri_aziendali.yml). Si può:

- **escludere server**, per nome o con un modello come `sap-*`, oppure interi gruppi dell'inventario, scrivendo il motivo. I server esclusi non vengono nemmeno contattati e nel rapporto risultano "escluso", con il motivo;
- **cambiare le soglie**: memoria minima, spazio in `/var` e `/boot`, quante ore vale il `leapp preupgrade`, architetture ammesse;
- **scegliere la versione di arrivo** per tutti, per gruppo o per server;
- **chiedere la conferma del backup** per le macchine fisiche, le virtuali o entrambe. La conferma si scrive nei criteri (`backup_confermato: true`) o si dà al lancio con `-e upgrade_backup_confermato=true`;
- **vietare pacchetti**: se sono installati, l'upgrade non parte;
- **bloccare per la sicurezza**: aggiornamenti gravi mancanti o falle ancora senza correzione;
- **aggiungere controlli propri**: comandi che il ruolo lancia sul server, con la regola per dire se sono passati (`rc_zero`, `rc_diverso_da_zero`, `contiene: testo`, `non_contiene: testo`) e il messaggio d'errore. Ognuno può bloccare o dare solo un avviso. Devono essere comandi che leggono soltanto.

Le regole valgono in quest'ordine: generali, poi del gruppo, poi del server, poi quelle date al lancio. I controlli propri si sommano.

## Far partire l'upgrade

```bash
ansible-playbook -i inventario LeappPreupgrade.yaml
```

```bash
ansible-playbook -i inventario LeappUpgrade.yaml
```

`LeappUpgrade.yaml` rifà tutti i controlli. Poi, solo sui server con il via libera:

1. lancia `leapp upgrade` con la destinazione esatta;
2. riavvia, aspettando fino a due ore;
3. controlla che il server sia arrivato alla versione nuova.

Va un server alla volta: per farne di più insieme si usa `-e upgrade_quanti_insieme=3`. Se uno si ferma con un errore, i successivi non partono.

## Farlo girare da solo ogni giorno

Con cron, sul computer da cui si lancia Ansible. Il giro di ogni giorno è solo il consigliere: l'upgrade lo fa partire sempre una persona.

```cron
30 6 * * * cd /percorso/Upgrade_in_place_rh9 && ansible-playbook -i inventario consiglia_upgrade.yml >> rapporti/giro.log 2>&1
```

## Versione di Ansible

- Server RHEL 9 e 10: va bene qualsiasi ansible-core recente.
- Server RHEL 8: ansible-core 2.17 e successivi non usano più il Python 3.6 di sistema. Si può installare un Python più nuovo sul server (`dnf install python3.11`, e poi `ansible_python_interpreter=/usr/bin/python3.11` nell'inventario), oppure usare ansible-core 2.16.
- Server RHEL 7: serve ansible-core 2.16, l'ultimo che lavora con Python 2.7.

## Prove

La logica dei consigli e dei blocchi ha le sue prove, che non hanno bisogno di Ansible:

```bash
cd roles/upgrade_advisor && python3 -m unittest discover -s tests
```

Il ruolo è stato provato su container UBI 7.9, 8.10 e 9.8, con ansible-core 2.16 e 2.22, insieme a criteri aziendali con gruppi, esclusioni e controlli propri. Sono immagini, non server veri: niente kernel e niente Leapp vero. Il via libera e l'avvio di `leapp upgrade` sono stati provati con un Leapp finto, che si ferma apposta. Il riavvio e l'arrivo alla versione nuova non sono ancora stati provati su una macchina vera.

## I playbook dell'upgrade

| File | Cosa fa |
|---|---|
| `InstallEnv2Leapp-Physical.yaml` | Server fisico RHEL 7: monta il DVD della RHEL 8, lo serve via http e installa Leapp da un repository locale |
| `InstallEnv2Leapp.yaml` | Macchina virtuale RHEL 8: lo stesso con il DVD della RHEL 9 |
| `LeappPreupgrade.yaml` | Lancia `leapp preupgrade` senza registrazione e conferma le risposte richieste |
| `LeappUpgrade.yaml` | Rifà i controlli e lancia `leapp upgrade` con il riavvio, solo sui server con il via libera |
| `PostUpgradeTasks.yaml` | Dopo l'upgrade: toglie i kernel vecchi e il repository di Leapp |
| `PostRhel9.6Tasks.yaml` | Dopo l'upgrade a RHEL 9: pulisce le esclusioni di Leapp in `dnf.conf` e i file di appoggio |
