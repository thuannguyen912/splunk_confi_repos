��    �      �  �   <      �     �     �       ^     K   x     �     �     �     �     �     �     �     �  +  �     %  	   -  �   7  7   �  W   	     a     w     |     �  "   �  $   �  %   �       1     o   ?  �   �  '   7  :   _     �     �  '   �  �   �  5   m     �     �  	   �  
   �  
   �  @   �  $   $      I      P      X   �   g      !     !  O   !  �   n!     �!      "     	"     "     ."  T   6"     �"  	   �"     �"     �"     �"     �"     #  1   -#  W   _#  G   �#     �#     $     $     <$     C$     J$     ^$     e$     j$  T   �$     �$     �$  2   �$     +%     ;%     Y%     e%     u%     �%     �%     �%  
   �%  
   �%     �%  	   �%     �%     �%     �%     �%     �%     &     &  )   &      ?&     `&     r&  $   x&  &  �&  -   �'  |  �'     o)     �)     �)     �)     �)     �)     �)     �)     �)     �)  
   �)  .   �)     !*     &*  �   C*     
+     +     +     +     %+     1+     =+  a   I+  �   �+     m,     v,  	   �,  �   �,  �   .-  &  �-  |   #/     �/     �/  
   �/     �/  ~   �/  	   I0     S0     `0     m0  	   q0     {0     ~0     �0  	   �0     �0     �0  #   �0     �0  	   �0  
   �0     �0     �0     1     1     1  	   (1     21     :1     >1     C1     F1     K1     P1     `1     o1     {1     �1     �1  -  �1     �2  (   �2     �2  �   3  d   �3     �3     �3     �3     4     4     "4     )4     14  }  74     �?     �?  �   �?  Q   �@  r   �@     ZA     rA  &   yA     �A  7   �A  ;   �A  )   B     FB  ?   MB  ~   �B  �   C  5   �C  K   D     ^D     ~D  =   �D  �   �D  Y   ME     �E  *   �E     �E     �E     F  f   *F  6   �F  	   �F  	   �F     �F  �   �F     �G     �G  b   �G  �   KH     �H     �H     I  6   I     GI  ^   OI  8   �I     �I     �I  4   J  7   ;J  *   sJ     �J  6   �J  a   �J  Z   LK     �K  -   �K  ,   �K     L     L     L     9L     BL  )   JL  z   tL     �L     �L  ?   M     OM  1   cM     �M     �M     �M     �M     �M     �M     N     N     )N  
   0N     ;N     AN     ZN     ^N     pN     vN     zN  9   �N  7   �N     O     O  >   $O  �  cO  K   �P  �  @Q     @S     `S     tS     �S     �S     �S     �S     �S     �S     �S  
   �S  C   T     JT  &   RT    yT     �U     �U  	   �U     �U     �U     �U     �U  |   �U  �   KV     =W     CW     VW  �   fW    6X  t  UY  �   �Z     i[     u[     {[     �[  �   �[     �\     �\     �\     �\     �\     �\     �\     �\  	   ]     ]     ]  /   #]     S]     W]     c]     r]     �]     �]     �]     �]  	   �]     �]     �]     �]     �]     �]     �]     �]     �]     �]     ^     ^     !^            �       K       .   @   A   ^       t   r   v   D   \   
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
Language: fr
X-Generator: Poedit 2.4.1
  à   devant « Utilisation des données »  sur  « Complet » inclut les manifestes des buckets et les fichiers de métadonnées, si le composant index_files est sélectionné. « Léger » liste uniquement les buckets chauds, si le composant index_listing est sélectionné. %s %s Données %s Utilisation des données 1 Go 1 Mo 10 Mo 100 Mo 5 Go <form class="form-horizontal form-complex">
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_component">Nom</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.component" id="outputtelemetry_component" placeholder="component.name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_input">Champ d’entrée</label>

        <div class="controls">
            <input type="text" class="input-xlarge" name="action.outputtelemetry.param.input" id="outputtelemetry_component" placeholder="field name"/>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_type">Type de données</label>

        <div class="controls">
            <label class="radio" for="outputtelemetry_type_event">
                <input id="outputtelemetry_type_event" type="radio" name="action.outputtelemetry.param.type" value="event"/>
                Événement
            </label>
            <label class="radio" for="outputtelemetry_type_aggregate">
                <input id="outputtelemetry_type_aggregate" type="radio" name="action.outputtelemetry.param.type" value="aggregate"/>
                Agrégat
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Catégories (au moins 1):</label>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_anonymous">
                <input type="checkbox" name="action.outputtelemetry.param.anonymous" id="outputtelemetry_anonymous" value="1"/>
                Données d’utilisation anonymisées
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_support">
                <input type="checkbox" name="action.outputtelemetry.param.support" id="outputtelemetry_support" value="1"/>
                Données d’utilisation de l’assistance 
            </label>
        </div>
        <div class="controls">
            <label class="checkbox" for="outputtelemetry_license">
                <input type="checkbox" name="action.outputtelemetry.param.license" id="outputtelemetry_license" value="1"/>
                Données d’utilisation des licences
            </label>
        </div>
    </div>
    <div class="control-group">
        <label class="control-label" for="outputtelemetry_optinrequired">Consentement requis</label>

        <div class="controls">
            <select id="outputtelemetry_optinrequired" name="action.outputtelemetry.param.optinrequired">
                <option value="1">1 - Splunk 6.5</option>
                <option value="2">2 - Splunk 6.6</option>
                <option value="3">3 - Splunk 7.0</option>
            </select>
        </div>
    </div>
</form>
 Actions Tous les rôles Tous les fichiers correspondant aux patterns donnés seront exclus. Pour exclure plusieurs fichiers, utilisez des jokers ou fournissez une liste de fichiers ou de patterns séparés par des virgules. Voulez-vous vraiment désactiver le partage des données d’utilisation de %s ? Tentative de suppression des logs de certains termes de recherche pouvant permettre une identification personnelle Activé automatiquement Retour Depuis le début de la semaine ouvrée Annuler Impossible de supprimer le diagramme ayant l’état %s Impossible de télécharger le diagramme ayant l’état %s Modifiez vos paramètres en cliquant sur  Fermer Combine les champs spécifiés en un JSON sous forme de chaîne Combine l’ensemble spécifié de noms de champs ou de patterns de noms de champs \
et crée un champ avec le nom résultant. Configurez les paramètres de rapports automatiques, affichez les données collectées, exportez les données dans un fichier, travaillez avec les fichiers de diagnostic et envoyez les données dans Splunk.  Configurez les paramètres des rapports automatiques. Configurez les paramètres de bundle à appliquer à toutes les instances.  Configurez l’instrumentation. Créer Créez de nouveaux diagrammes à l’aide du bouton ci-dessus Créez une chaîne JSON : { "name": "<value of name>", "data": { "count": <value of data.count>, "metrics": [valeurs de data.metrics] }} Action personnalisée pour envoyer les résultats au point de terminaison télémétrique Données Planification de transmission des données Type de données Période définie par une date Période définie par une date Les plages de dates supérieures à 1 an sont tronquées à une année à compter de la plus récente Les plages de date doivent être inférieures à 1 an Supprimer Supprimé Log de diagnostic Les fichiers de diagnostic contiennent des informations sur votre déploiement Splunk, comme les fichiers de configuration et les logs, pour aider l’Assistance Splunk à diagnostiquer et résoudre les problèmes.  Désactiver la limite Désactivé Désactiver cela peut nuire à la résolution des problèmes et au support de votre installation.  Désactiver cela va exclure vos données d’utilisation des données prises en compte par Splunk pour apporter des améliorations à nos produits et services.  N'existe pas Télécharger Modifier Modifier la planification de transmission des données Activé Erreur de communication avec Splunk. Veuillez vérifier votre connexion réseau et réessayer. Erreur lors de la récupération de la liste de serveurs Erreur : %s Tous les %s à %s Exclure les fichiers etc d’un volume supérieur à Exclure les fichiers de log d’un volume supérieur à Exclure les fichiers de log antérieurs à Exclure des patterns Exclut les gros fichiers du répertoire etc de Splunk. Exclut les gros fichiers du répertoire var/log de Splunk, si le composant log est sélectionné. Exclut les fichiers de log antérieurs à un âge donné en jours. 0 désactive ce filtre. Exporter Exporter/envoyer les données d’utilisation Exportation des données d’instrumentation Échec Filtre Filtrer les termes de recherche Vendredi Complet Obtenir tous les fichiers .dmp d’erreur Si vous sélectionnez « Non », collecte au plus trois fichiers .dmp de Windows, si le composant log est sélectionné. En cours Inclure des composants Inclure les fichiers de lookup dans les composants etc et pool. Inclure les lookups Niveau d’énumération du répertoire d’index Fichiers d’index Instrumentation Instrumentation | Splunk 24 dernières heures 30 derniers jours 7 derniers jours En savoir plus En savoir plus Léger Manifestes Lundi Depuis le début du mois Nom Nouveau diagramme Suiv. Non Aucun diagramme trouvé Aucune donnée disponible pour la période sélectionnée Aucune donnée envoyée au cours des 30 derniers jours Aucun résultat trouvé. Nœuds Envoyer les résultats au point de terminaison télémétrique Envoie les résultats de recherche au point de terminaison télémétrique à l’aide du champ nommé « data ». Chacun sera \
nommé « my.telemetry » et est décrit comme un type d’« event » unique. L’événement de télémétrie ne sera \
envoyé que si, dans le déploiement, le partage des données d’utilisation anonymisées a été accepté, avec la version 2 du consentement. Envoie les résultats de recherche au point de terminaison télémétrique. Envoie les résultats de recherche au point de terminaison télémétrique. \
Le champ obligatoire « input » aura la charge utile du point de terminaison. \
Les autres champs « component », « type » et « optinrequired » \
sont des champs optionnels mais le point de terminaison s’attend à ce qu’ils soient fournis, soit dans la commande de recherche, \
soit dans les données d’événement.\
Les champs de visibilité « anonymous », « license » et « support » sont optionnels. La semaine ouvrée précédente Le mois précédent La semaine précédente L'année précédente Mis en file d'attente Recréer Rétablir l’état par défaut Rôles Samedi Enregistrer Planifié  Sélectionnez l’instance dont vous voulez collecter les données. Envoyer Envoi des données d’instrumentation Le partage des données d’utilisation des logiciels aide Splunk Inc. à optimiser votre déploiement, hiérarchiser nos fonctionnalités, améliorer votre expérience, vous informer de la publication de correctifs et développer des fonctionnalités de haute qualité.  Taille Statut Réussite Dimanche TestHeader1 TestHeader2 TestHeader3 Cette application connecte l’instance Splunk qui héberge aux services de collecte des données d’utilisation de Splunk. Cette liste présente les instances connectées à cette search head. Si vous avez configuré la Console de Monitoring en mode distribué, utilisez cette instance pour collecter des données après d’instances qui ne sont pas listées ici. Jeudi Heure de création Heure d’envoi Pour assurer la conformité à l’offre que vous avez achetée, nous recueillons des données sur votre consommation de licences. Ces données sont liées à votre compte au moyen du GUID de votre licence.  Afin d’améliorer nos produits et nos offres, nous recueillons des données agrégées sur l’utilisation des fonctionnalités, les performances, la topologie de déploiement, l’infrastructure et l’environnement d’exploitation. Ces données ne sont pas liées à votre compte.  Pour vous apporter une assistance efficace et vous aider à dépanner et améliorer votre installation, nous recueillons des données agrégées sur l’utilisation des fonctionnalités de ce déploiement, ses performances, sa topologie, son infrastructure et son environnement d’exploitation. Ces données sont liées à votre compte au moyen du GUID de votre licence.  Pour connaître le nombre de clients qui utilisent des versions anciennes de Splunk, nous recueillons des données agrégées sur les versions des logiciels.  Aujourd'hui Mardi Utilisation des données Afficher dans la recherche :  Affichez les données de consommation de licences, les données d’utilisation anonymisées et les données d’utilisation de l’assistance qui ont été recueillies (n’inclut pas les données des sessions de navigateur).  Mercredi Depuis le début de la semaine Depuis le début de l'année Oui Hier am corps conf_replication_summary consensus jour distribution p. ex. *.csv pour exclure tous les fichiers csv etc chaque jour chaque semaine file_validate pied de page index_files index_listing instance instances kvstore log page. pm pool rest results::filter results::write searchpeers sélectionné static-content erreur inconnue 