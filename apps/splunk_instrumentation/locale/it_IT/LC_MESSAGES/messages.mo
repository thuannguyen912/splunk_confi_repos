��    �      �  �   <      �     �     �       ^     K   x     �     �     �     �     �     �     �     �  +  �     %  	   -  �   7  7   �  W   	     a     w     |     �  "   �  $   �  %   �       1     o   ?  �   �  '   7  :   _     �     �  '   �  �   �  5   m     �     �  	   �  
   �  
   �  @   �  $   $      I      P      X   �   g      !     !  O   !  �   n!     �!      "     	"     "     ."  T   6"     �"  	   �"     �"     �"     �"     �"     #  1   -#  W   _#  G   �#     �#     $     $     <$     C$     J$     ^$     e$     j$  T   �$     �$     �$  2   �$     +%     ;%     Y%     e%     u%     �%     �%     �%  
   �%  
   �%     �%  	   �%     �%     �%     �%     �%     �%     &     &  )   &      ?&     `&     r&  $   x&  &  �&  -   �'  |  �'     o)     �)     �)     �)     �)     �)     �)     �)     �)     �)  
   �)  .   �)     !*     &*  �   C*     
+     +     +     +     %+     1+     =+  a   I+  �   �+     m,     v,  	   �,  �   �,  �   .-  &  �-  |   #/     �/     �/  
   �/     �/  ~   �/  	   I0     S0     `0     m0  	   q0     {0     ~0     �0  	   �0     �0     �0  #   �0     �0  	   �0  
   �0     �0     �0     1     1     1  	   (1     21     :1     >1     C1     F1     K1     P1     `1     o1     {1     �1     �1  -  �1     �2     �2     �2  c   �2  Q   ]3     �3     �3     �3     �3     �3     �3     �3     �3  B  �3     -?     4?  �   B?  5   �?  u   2@     �@     �@  "   �@     �@  ,   �@  ,   #A  +   PA     |A  2   �A  s   �A  �   *B  0   �B  F   �B     ;C     XC  3   ]C  �   �C  H   D     bD  #   gD     �D     �D     �D  b   �D  7   !E     YE  	   aE     kE  �   {E     <F     NF  s   [F  �   �F  
   WG     bG     kG  ,   tG  	   �G  Z   �G  2   H  
   9H     DH  *   TH  -   H  "   �H     �H  B   �H  k   #I  `   �I     �I     �I  0   J     HJ     UJ     \J     {J     �J     �J  ]   �J     	K     K  3   %K     YK  '   hK     �K     �K     �K     �K     �K     �K     �K     L     #L  	   )L     3L     ;L     NL     SL     bL     iL     lL  >   �L  *   �L     �L     	M  -   M  r  <M  >   �N  �  �N     �P     �P     �P     �P     �P     �P     �P     Q     Q     Q      Q  3   -Q     aQ  )   gQ    �Q  
   �R     �R     �R     �R     �R     �R     �R  o   �R  �   WS     :T     CT     TT  �   aT  �   U  N  �U  �   >W     �W     �W     �W     �W  �   	X  
   �X     �X     �X     �X     �X     �X     �X     �X  	   �X     Y     
Y  +   Y     <Y     @Y     LY     [Y     iY     xY     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     �Y     Z     Z            �       K       .   @   A   ^       t   r   v   D   \   
       f                  R   `   >   +   T   Q       �   5          �   #   8           �   Z              '   �   -       ;   c          H   �   �   �       �   V   �   W   E   _           3   �   �   I          p   b   �   w      �   9       C                  U   e   �   	   (   <   "   �   ]          �   u      �   *       z       S   �           m          �   x      �               ?   �   �      i   $          �   )      /   F   O   7                   0   4   h      g   �       �   }   a   �          �   G   =   �   �   [       �   �   ~   M       J   1      �      �      P       l   ,       j       �      �       �   �           L           n   �      %   k   �   �      X   �       y   �   �   2             �   �   s   &   q   Y   d   B   �                  �   �                   :          {   �      6   !       |          �   o   N     at   next to "Usage Data"  on  "Full" includes bucket manifests and metadata files, if the index_files component is selected. "Light" lists only hot buckets, if the index_listing component is selected. %s %s Data %s Usage Data 1 GB 1 MB 10 MB 100 MB 5 GB <form class="form-horizontal form-complex">
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_component">Name</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.component" id="outputtelemetry_component" placeholder="component.name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_input">Input field</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.input" id="outputtelemetry_component" placeholder="field name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_type">Data type</label>

        <div class="controls">
            <label class="radio" for="outputtelemetry_type_event">
                <input id="outputtelemetry_type_event" type="radio" name="action.outputtelemetry.param.type" value="event"/>
                Event
            </label>
            <label class="radio" for="outputtelemetry_type_aggregate">
                <input id="outputtelemetry_type_aggregate" type="radio" name="action.outputtelemetry.param.type" value="aggregate"/>
                Aggregate
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Categories (at least 1):</label>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_anonymous">
                <input type="checkbox" name="action.outputtelemetry.param.anonymous" id="outputtelemetry_anonymous" value="1"/>
                Anonymized usage data
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_support">
                <input type="checkbox" name="action.outputtelemetry.param.support" id="outputtelemetry_support" value="1"/>
                Support usage data
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_license">
                <input type="checkbox" name="action.outputtelemetry.param.license" id="outputtelemetry_license" value="1"/>
                License usage data
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_optinrequired">Required opt-in</label>

        <div class="controls">
            <select id="outputtelemetry_optinrequired" name="action.outputtelemetry.param.optinrequired">
                <option value="1">1 - Splunk 6.5</option>
                <option value="2">2 - Splunk 6.6</option>
                <option value="3">3 - Splunk 7.0</option>
            </select>
        </div>
    </div>
</form>
 Actions All Roles All files matching the given patterns will be excluded. To exclude multiple files, use wildcards, or provide a comma-separated list of files or patterns. Are you sure you want to disable %s usage data sharing? Attempt to redact search terms from logs that may be private or personally identifying. Automatically enabled Back Business week to date Cancel Cannot delete diag with status: %s Cannot download diag with status: %s Change your settings by clicking the  Close Combines specified fields into a stringified JSON Combines the specified set of field names, or field name patterns, \
and creates an field with the output name. Configure automated reporting settings, view collected data, export data to file, work with diagnostic files, and send data to Splunk.  Configure automated reporting settings. Configure bundle settings to be applied to all instances.  Configure instrumentation. Create Create New Diags using the button above Create a stringified JSON: { "name": "<value of name>", "data": { "count": <value of data.count>, "metrics": [values of data.metrics] }} Custom action to output results to telemetry endpoint Data Data Transmission Schedule Data Type Date Range Date range Date ranges more than 1 year are truncated to a year from latest Date ranges must be less than 1 year Delete Deleted Diagnostic Log Diagnostic files contain information about your Splunk deployment, such as configuration files and logs, to help Splunk Support diagnose and resolve problems.  Disable limit Disabled Disabling this may hinder troubleshooting and support for your implementation.  Disabling this will exclude your usage data from the data Splunk considers when making improvements to our products and services.  Does not exist Download Edit Edit Data Transmission Schedule Enabled Error communicating with Splunk. Please check your network connection and try again. Error fetching list of servers Error: %s Every %s at %s Exclude etc files larger than Exclude log files larger than Exclude log files older than Exclude patterns Excludes large files in the Splunk etc directory. Excludes large files in the Splunk var/log directory, if the log component is selected. Excludes log files beyond an age given in days. 0 disables this filter. Export Export/Send Usage Data Exporting instrumentation data Failed Filter Filter search terms Friday Full Get every crash .dmp file If "No", gathers at most three Windows .dmp files, if the log component is selected. In progress Include components Include lookup files in the etc & pool components. Include lookups Index directory listing level Index files Instrumentation Instrumentation | Splunk Last 24 hours Last 30 days Last 7 days Learn More Learn more Light Manifests Monday Month to date Name New Diag Next No No Diags found No data available for selected time range No data sent in the last 30 days No results found. Nodes Output results to telemetry endpoint Output search results to the telemetry endpoint, using the field named "data."" Each will be \
named "my.telemetry" and is described as a singular "event" type. The telemetry event will only be \
sent if the deployment has been opted in to share Anonymized usage data, with opt-in version of 2. Outputs search results to telemetry endpoint. Outputs search results to telemetry endpoint. \
Required field “input” will have the endpoint payload. \
The other fields “component”, “type”, “optinrequired” \
are optional fields but the endpoint expects them to be supplied either with the search command \
or to be found in the event data.\
Visibility fields "anonymous", "license" and "support" are optional. Previous business week Previous month Previous week Previous year Queued Recreate Revert to default Roles Saturday Save Scheduled  Select instance you want to collect data from. Send Sending instrumentation data Sharing your software usage data helps Splunk Inc. optimize your deployment, prioritize our features, improve your experience, notify you of patches, and develop high quality product functionality.  Size Status Success Sunday TestHeader1 TestHeader2 TestHeader3 This application connects the hosting Splunk instance to Splunk's usage data collection services. This list shows the instances connected to this search head. If you have configured Monitoring Console in distributed mode, use that instance to collect data from any instances not listed here. Thursday Time Created Time Sent To ensure compliance with your purchased offering, we collect data about your license consumption. This data is linked to your account using your license GUID.  To improve our products and offerings, we collect aggregated data about feature usage, performance, deployment topology, infrastructure, and operating environment. This data is not linked to your account.  To provide you enhanced support and help you troubleshoot and improve your implementation, we collect aggregated data about this deployment's feature usage, performance, deployment topology, infrastructure and operating environment. This data is linked to your account using your license GUID.  To understand the number of customers using older versions of Splunk software, we collect aggregated software version data.  Today Tuesday Usage Data View in Search:  View license usage, anonymized usage, and support usage data that has been collected (does not include browser session data).  Wednesday Week to date Year to date Yes Yesterday am body conf_replication_summary consensus day dispatch e.g. *.csv to exclude all csv files etc every day every week file_validate footer index_files index_listing instance instances kvstore log page pm pool rest results::filter results::write searchpeers selected static-content unknown error Project-Id-Version: PROJECT VERSION
Report-Msgid-Bugs-To: EMAIL@ADDRESS
PO-Revision-Date: 2020-09-07 13:41+0100
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Generated-By: Babel 2.6.0
Last-Translator: 
Language-Team: 
Language: it
X-Generator: Poedit 2.4.1
  alle   accanto a "Dati di utilizzo"  su  "Full" include manifesti di bucket e file di metadati, se è selezionato il componente index_files. "Light" include solo i bucket hot, se è selezionato il componente index_listing. %s %s dati %s dati di utilizzo 1 GB 1 MB 10 MB 100 MB 5 GB <form class="form-horizontal form-complex">
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_component">Nome</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.component" id="outputtelemetry_component" placeholder="component.name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_input">Campo di input</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.input" id="outputtelemetry_component" placeholder="field name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_type">Tipo di dati</label>

        <div class="controls">
            <label class="radio" for="outputtelemetry_type_event">
                <input id="outputtelemetry_type_event" type="radio" name="action.outputtelemetry.param.type" value="event"/>
                Evento
            </label>
            <label class="radio" for="outputtelemetry_type_aggregate">
                <input id="outputtelemetry_type_aggregate" type="radio" name="action.outputtelemetry.param.type" value="aggregate"/>
                Aggregato
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Categorie (almeno 1):</label>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_anonymous">
                <input type="checkbox" name="action.outputtelemetry.param.anonymous" id="outputtelemetry_anonymous" value="1"/>
                Dati di utilizzo anonimi
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_support">
                <input type="checkbox" name="action.outputtelemetry.param.support" id="outputtelemetry_support" value="1"/>
                Dati di utilizzo supporto
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_license">
                <input type="checkbox" name="action.outputtelemetry.param.license" id="outputtelemetry_license" value="1"/>
                Dati di utilizzo licenza
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_optinrequired">Consenso richiesto</label>

        <div class="controls">
            <select id="outputtelemetry_optinrequired" name="action.outputtelemetry.param.optinrequired">
                <option value="1">1 - Splunk 6.5</option>
                <option value="2">2 - Splunk 6.6</option>
                <option value="3">3 - Splunk 7.0</option>
            </select>
        </div>
    </div>
</form>
 Azioni Tutti i ruoli Tutti i file che corrispondono ai pattern forniti verranno esclusi. Per escludere più file, utilizzare i caratteri jolly oppure fornire un elenco separato da virgole di file o pattern. Disabilitare la condivisione dei dati di utilizzo %s? Tentare di oscurare i termini di ricerca dai log che possono essere privati o consentire l'identificazione personale. Abilitato automaticamente Indietro Inizio settimana lavorativa a oggi Annulla Impossibile eliminare diagnosi con stato: %s Impossibile scaricare diagnosi con stato: %s Modificare le impostazioni facendo clic su  Chiudi Combina i campi specificati in un JSON di stringhe Combina la serie specificata di nomi di campo, o pattern di nomi di campo, \
e crea un campo con il nome di output. Configura le impostazioni dei report automatici, visualizza i dati raccolti, esporta i dati su file, esegui i file diagnostici e invia i dati a Splunk.  Configura le impostazioni dei report automatici. Configura le impostazioni del bundle da applicare a tutte le istanze.  Configura la strumentazione. Crea Crea nuove diagnosi utilizzando il pulsante in alto Crea un JSON di stringhe: { "name": "<value of name>", "data": { "count": <value of data.count>, "metrics": [valori di data.metrics] }} Azione personalizzata per trasferire i risultati all'endpoint telemetria Dati Pianificazione di trasmissione dati Tipo di dati Intervallo di date Intervallo di date Gli intervalli di date superiori a 1 anno vengono troncati a decorrere da un anno dall'ultima data Gli intervalli di date devono essere inferiori a 1 anno Elimina Eliminato Log diagnostico I file diagnostici contengono informazioni sul proprio deployment di Splunk, quali file di configurazione e log, per aiutare il Supporto Splunk a diagnosticare e risolvere eventuali problemi.  Disabilita limite Disabilitato Disabilitare questa opzione può impedire la risoluzione dei problemi e l'assistenza per l'implementazione in uso.  Disabilitare questa opzione esclude i dati di utilizzo dai dati che Splunk considera quando esegue migliorie ai prodotti e ai servizi.  Non esiste Download Modifica Modifica pianificazione di trasmissione dati Abilitato Errore durante la comunicazione con Splunk. Verificare la connessione di rete e riprovare. Errore durante il recupero degli elenchi di server Errore: %s Ogni %s alle %s Escludi file etc di dimensione superiore a Escludi file di log di dimensione superiore a Escludi file di log più vecchi di Escludi pattern Esclude i file di grandi dimensioni nella directory etc di Splunk. Esclude i file di grandi dimensioni nella directory var/log di Splunk, se è selezionato il componente log. Esclude i file di log oltre un'età predefinita, indicata in giorni. 0 disabilita questo filtro. Esporta Esporta/Invia dati di utilizzo Esportazione dei dati di strumentazione in corso Non riuscito Filtro Filtra i termini della ricerca Venerdì Intera Ottieni ogni file di crash .dmp Se "No", acquisisce al massimo tre file .dmp di Windows, se è selezionato il componente log. In corso Includi componenti Includi file di lookup nei componenti etc e gruppo. Includi lookup Livello di elenco directory dell'indice File di indice Strumentazione Strumentazione | Splunk Ultime 24 ore Ultimi 30 giorni Ultimi 7 giorni Ulteriori informazioni Ulteriori informazioni Light Manifesti Lunedì Inizio mese a oggi Nome Nuova diagnosi Avanti No Nessuna diagnosi trovata Nessun dato disponibile per l'intervallo temporale selezionato Nessun dato inviato negli ultimi 30 giorni Nessun risultato trovato. Nodi Trasferisci risultati all'endpoint telemetria Trasferire i risultati della ricerca all'endpoint telemetria, utilizzando il campo denominato "data."" Ciascuno verrà \
nominato "my.telemetry" e descritto come un tipo singolare di "event". L'evento di telemetria verrà \
inviato solo se il deployment prevede il consenso alla condivisione dei Dati di utilizzo anonimi, con versione 2 del modulo di consenso esplicito. Trasferisce i risultati della ricerca all'endpoint telemetria. Trasferisce i risultati della ricerca all'endpoint telemetria. \
Il campo obbligatorio “input” avrà il payload dell'endpoint. \
Gli altri campi, “component”, “type”, “optinrequired”, \
sono facoltativi, ma l'endpoint si attende che vengano forniti mediante il comando di ricerca \
o che si trovino nei dati dell'evento.\
I campi di visibilità "anonymous", "license" e "support" sono facoltativi. Settimana lavorativa precedente Mese precedente Settimana precedente Anno precedente In coda Ricrea Ritorna ai valori di default Ruoli Sabato Salva Pianificato  Selezionare l'istanza dalla quale acquisire i dati. Invia Invio dei dati di strumentazione in corso La condivisione dei dati di utilizzo del software aiuta Splunk Inc. a ottimizzare il tuo deployment, stabilire una priorità tra le funzioni, migliorare la tua esperienza, informarti delle patch disponibili e sviluppare funzionalità di elevata qualità per i prodotti.  Dimensioni Stato Successo Domenica TestHeader1 TestHeader2 TestHeader3 Questa applicazione connette l'istanza che ospita Splunk ai servizi di raccolta dei dati di utilizzo di Splunk. Questo elenco mostra le istanze collegate a questa search head. Se hai configurato la Console di monitoraggio in modalità distribuita, utilizza tale istanza per raccogliere dati da qualsiasi istanza non contenuta nell'elenco. Giovedì Ora di creazione Ora di invio Per garantire la conformità all'offerta acquistata, raccogliamo dati sul consumo della licenza. Questi dati sono collegati al tuo account mediante il GUID della licenza.  Per migliorare i nostri prodotti e le offerte, raccogliamo dati aggregati su utilizzo delle funzioni, performance, topologia del deployment, infrastruttura e ambiente operativo. Questi dati non sono collegati al tuo account.  Per fornire un supporto eccellente e aiutarti a risolvere i problemi e migliorare l'implementazione in uso, raccogliamo dati aggregati su utilizzo delle funzioni, performance, topologia del deployment, infrastruttura e ambiente operativo di questo deployment. Questi dati sono collegati al tuo account mediante il GUID della licenza.  Per conoscere il numero di clienti che utilizza versioni meno recenti del software Splunk, raccogliamo dati aggregati sulle versioni del software.  Oggi Martedì Dati di utilizzo Visualizza in Ricerca:  Visualizza i dati di utilizzo licenza, anonimi e di supporto che sono stati raccolti (non include i dati relativi alle sessioni del browser).  Mercoledì Inizio settimana a oggi Inizio anno a oggi Sì Ieri am corpo conf_replication_summary consensus giorno invio ad es. *.csv per escludere tutti i file csv etc ogni giorno ogni settimana file_validate piè di pagina index_files index_listing istanza istanze kvstore log pagina pm gruppo rest risultati::filtra risultati::scrivi peer di ricerca selezionato static-content errore sconosciuto 