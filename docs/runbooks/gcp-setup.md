# Runbook — infra GCP do agenda-service (consulta de agenda)

Projeto: `brikz-ap` (mesmo projeto do `optin-service` e do `contrato-service`), região
`southamerica-east1`, conta `ricardo@brikz.ai` — decisão explícita: os três serviços
compartilham APIs habilitadas, Artifact Registry (repositórios separados) e a MESMA
instância Cloud SQL (`optin-pg`), um schema Postgres por serviço dentro de cada banco
`ap_<cnpj>`. Ver `docs/superpowers/specs/2026-08-24-agenda-service-design.md`.

**Estado deste documento: executado em 2026-09-03, agenda-service no ar em homolog.**
`https://agenda-service-6sy5bhymwq-rj.a.run.app` — `/health` 200, `/agendas/urs` sem JWT
401 (da aplicação), com JWT do tenant 200. Cada seção abaixo tem uma nota "Feito em
2026-09-03"; repita o `describe`/`list` de verificação antes de recriar algo.

## 0. Sessão

    gcloud config set project brikz-ap
    gcloud config set account ricardo@brikz.ai

## 1. APIs e Artifact Registry

As 8 APIs base (`run`, `sqladmin`, `secretmanager`, `cloudbuild`, `artifactregistry`, `iam`,
`cloudresourcemanager`, `compute`) e `orgpolicy.googleapis.com` já foram habilitadas pelo
`optin-service` neste projeto — confirme com `gcloud services list --enabled` em vez de
reabilitar. Este serviço adiciona duas:

    gcloud services enable pubsub.googleapis.com cloudscheduler.googleapis.com

Repositório de imagens próprio (não reaproveita o `optin` do optin-service — cada serviço
com seu Artifact Registry, mesmo padrão dos irmãos):

    gcloud artifacts repositories create agenda --repository-format=docker --location=southamerica-east1 \
      --description="Imagens do agenda-service (consulta de agenda)"

Verificar: `gcloud artifacts repositories describe agenda --location=southamerica-east1`

Feito em 2026-09-03: `cloudscheduler.googleapis.com` habilitada (demais 8 + `pubsub` já vinham do
optin-service); repositório `agenda` criado
(`projects/brikz-ap/locations/southamerica-east1/repositories/agenda`, formato DOCKER).

## 2. Cloud SQL — schema no banco por tenant que o optin já usa

**Sem instância nova.** Reaproveita `optin-pg` e o banco `ap_<cnpj>` que o `optin-service`
já provisiona por tenant — cada serviço com seu próprio schema Postgres dentro desse banco,
não uma instância própria. Motivo: um Cloud SQL a menos pra operar/pagar, e o isolamento
por tenant (um banco por CNPJ) já está no nível certo; separar por instância só se o volume
real de `agenda_ur`/`agenda_ur_evento` (risco já registrado no design doc §15) forçar isso —
migração futura de um schema pra instância própria é mecânica (dump/restore), não bloqueia
a decisão de hoje.

**Achado importante:** `sql/schema/01-agenda-schema.sql` do agenda-service e
`db/migrations/0001_baseline.sql` do optin-service criam tabelas com **nomes idênticos**
(`cerc_requisicao`, `webhook_inbox`, `dominio_arranjo`). No schema `public` do mesmo banco
elas colidiriam. Por isso o schema `agenda` é obrigatório, não cosmético.

Papel/role de aplicação próprio (não reaproveita `optin_app`):

    PW_AGENDA_APP="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    gcloud sql users create agenda_app --instance=optin-pg --password="$PW_AGENDA_APP"

**Cuidado:** todo usuário criado via `gcloud sql users create` no Cloud SQL para Postgres
ganha a role `cloudsqlsuperuser` (permissão administrativa do Cloud SQL, diferente do
superuser real do Postgres) — isso NÃO concede acesso automático às tabelas de outro
usuário (GRANT/REVOKE do Postgres continua valendo normalmente), mas significa que o
isolamento por schema abaixo é defesa em profundidade contra acesso acidental por
`search_path`/query sem qualificação, não uma sandbox contra alguém de posse das
credenciais de `agenda_app` decidido a tentar `SET ROLE`/`CREATE`. Suficiente para o
objetivo aqui (dois serviços irmãos, mesmo time), não para multi-tenant hostil.

Por tenant já provisionado pelo optin-service (repita para cada `ap_<cnpj>` — via Cloud SQL
Connector, mesmo caminho de `scripts/apply_schema.py`, autenticado como `agenda_app`):

    CREATE SCHEMA IF NOT EXISTS agenda AUTHORIZATION agenda_app;
    ALTER ROLE agenda_app IN DATABASE "ap_<cnpj>" SET search_path TO agenda;

`agenda_app` é dono do próprio schema (schema criado por ele mesmo, com `CONNECT` já
concedido a `PUBLIC` por padrão no banco) — não precisa de uma conexão admin separada.
`scripts/apply_schema.py` e `shared/cloudsql_client.py` usam nomes de tabela sem
qualificar o schema; com `search_path=agenda` na role, tudo cai no lugar certo sem
mudança de código (só a checagem do ledger `schema_aplicado` foi ajustada para não
fixar `public.`, ver commit correspondente).

**Achado ao executar (2026-09-03):** `CREATE SCHEMA` falhou de início com `permission
denied for database ap_38138785000136` — Postgres 15+ não concede mais `CREATE` na
database para `PUBLIC` por padrão (mudança de versão, não é specífico do Cloud SQL), então
`agenda_app` recém-criado não tinha esse privilégio. Resolvido sem tocar no superusuário
`postgres` compartilhado: lido `ADMIN_DB_CONFIG` (credenciais de `optin_app`, dono do banco
por tê-lo criado) e rodado uma vez `GRANT CREATE ON DATABASE "ap_38138785000136" TO
agenda_app` com essa conexão. Depois disso `agenda_app` criou o próprio schema
normalmente. Repita esse grant pontual pra cada novo tenant antes do `CREATE SCHEMA`
daquele banco.

Guardar `PW_AGENDA_APP` só no segredo abaixo, nunca em log:

    printf '{"cloudsql_connection_name":"brikz-ap:southamerica-east1:optin-pg","cloudsql_db_user":"agenda_app","cloudsql_db_password":"%s","cloudsql_db_name":"ap_<cnpj>"}' "$PW_AGENDA_APP"
    unset PW_AGENDA_APP

(vira parte do segredo `AGENDA_TENANT_<cnpj>_CONFIG` da seção 9, junto com as credenciais
CERC e Basic do webhook daquele tenant — não existe um `ADMIN_DB_CONFIG` próprio aqui,
porque este serviço nunca cria banco, só schema dentro de um banco que o optin já criou.)

Rotação de senha: `gcloud sql users set-password agenda_app --instance=optin-pg --password=...`
e nova versão de cada `AGENDA_TENANT_<cnpj>_CONFIG`; reiniciar o serviço (cache por processo,
mesma ressalva do optin).

Feito em 2026-09-03: usuário `agenda_app` criado; schema `agenda` criado e com
`search_path` ajustado em `ap_38138785000136` (único tenant existente); confirmado via
`information_schema.tables` que `cerc_requisicao`/`webhook_inbox`/`dominio_arranjo`
caíram em `agenda`, não em `public` (sem colisão com as tabelas do optin-service). Os 5
arquivos de `sql/schema/*.sql` aplicados nesse banco com `scripts/apply_schema.py`.

## 3. Service accounts e IAM

    gcloud iam service-accounts create agenda-run --display-name="agenda-service runtime (Cloud Run)"
    gcloud iam service-accounts create agenda-build --display-name="agenda-service Cloud Build"
    for r in roles/cloudsql.client roles/secretmanager.secretAccessor; do
      gcloud projects add-iam-policy-binding brikz-ap --member=serviceAccount:agenda-run@brikz-ap.iam.gserviceaccount.com --role=$r --condition=None
    done
    for r in roles/run.admin roles/artifactregistry.writer roles/logging.logWriter roles/cloudbuild.builds.builder; do
      gcloud projects add-iam-policy-binding brikz-ap --member=serviceAccount:agenda-build@brikz-ap.iam.gserviceaccount.com --role=$r --condition=None
    done
    gcloud iam service-accounts add-iam-policy-binding agenda-run@brikz-ap.iam.gserviceaccount.com \
      --member=serviceAccount:agenda-build@brikz-ap.iam.gserviceaccount.com --role=roles/iam.serviceAccountUser

`agenda-run@` é também a identidade OIDC da push subscription do Pub/Sub e dos jobs do
Cloud Scheduler (seções 6-7) — não precisa de role de Pub/Sub/Scheduler pra isso: quem
assina o token é o serviço que INVOCA (Pub/Sub, Scheduler), `agenda-run@` só precisa
existir para ser citada como `--push-auth-service-account`/`--oidc-service-account-email`.
Quem cria a subscription/o job (você, seção 6-7) precisa de `roles/iam.serviceAccountUser`
sobre `agenda-run@` — mesmo binding acima já cobre se for a mesma conta (`agenda-build@`)
disparando; se você rodar essas seções manualmente como `ricardo@brikz.ai`, confirme que
sua conta tem esse papel ou rode como owner/editor do projeto.

`secretmanager.secretAccessor` em nível de projeto já cobre o segredo `IAM_JWT_PUBLIC_KEY`
existente (criado pelo optin-service) — nenhum grant extra por segredo é necessário.

Feito em 2026-09-03: `agenda-run@brikz-ap.iam.gserviceaccount.com` (cloudsql.client,
secretmanager.secretAccessor); `agenda-build@brikz-ap.iam.gserviceaccount.com` (run.admin,
artifactregistry.writer, logging.logWriter, cloudbuild.builds.builder) + serviceAccountUser
sobre `agenda-run@`.

## 4. Segredos estáticos do serviço

    python -c 'import secrets; print(secrets.token_urlsafe(50))' \
      | gcloud secrets create AGENDA_DJANGO_SECRET_KEY --data-file=- --replication-policy=user-managed --locations=southamerica-east1

**Sem par de chaves JWT novo.** Este serviço só valida token (nunca emite) — reaproveita o
segredo `IAM_JWT_PUBLIC_KEY` que o optin-service já criou no projeto (mesmo IdP corporativo,
mesma chave, `.env.example` já documenta isso). `--set-secrets` no `cloudbuild.yaml` aponta
pra ele sem recriar nada.

Feito em 2026-09-03: `AGENDA_DJANGO_SECRET_KEY` criado, versão 1.

## 5. Pub/Sub — tópico do webhook

    gcloud pubsub topics create agenda-webhook-inbox

A push subscription depende da URL real do Cloud Run (só existe depois do primeiro
deploy) — ver seção 8 ("primeiro deploy") antes de criar a subscription.

Feito em 2026-09-03: tópico `agenda-webhook-inbox` criado; subscription
`agenda-webhook-inbox-push` criada na seção 8 (push endpoint = `/api/v1/webhooks/agenda/processar`,
auth service account `agenda-run@`).

## 6. Cloud Scheduler — job de completude

Mesma dependência de URL da seção 5: criar depois do primeiro deploy (seção 8).

`varrer_completude` roda a cada ~30s no design doc (§8) — Cloud Scheduler não agenda
sub-minuto (cron padrão, granularidade mínima de 1 minuto). Rodar a cada 1 minuto é
suficiente: a janela de completude é 90s e o timeout duro é 15min, ambos com folga
confortável sobre um atraso de até ~60s entre execuções.

`importar_ap005` (design doc §9/§14 item 4) **não entra no Scheduler ainda** — a conexão
real do arquivo (SFTP/bucket/Connect:Direct) é uma dependência de infra não definida.
Fica como endpoint interno testável manualmente (curl + token OIDC) até essa decisão
existir; nenhum job agendado aponta pra ele por enquanto.

Feito em 2026-09-03: `agenda-varrer-completude` criado (`* * * * *`, alvo
`/api/v1/jobs/varrer-completude`, OIDC `agenda-run@`), `ENABLED`. Primeiro disparo
automático (poucos segundos após a criação) voltou `401` — mesma propagação de IAM/OIDC
já observada no runbook do optin (minutos, não instantâneo); disparos seguintes (`gcloud
scheduler jobs run` manual e o tick automático seguinte) voltaram `200`.

## 7. Lista de tenants dos jobs periódicos — limitação conhecida

`apps/agenda/views.py` tem `_TENANTS_JOBS_PERIODICOS` **hardcoded no código**
(design doc §14 ponto 3 — mesmo ponto em aberto que os serviços irmãos ainda não
resolveram: não existe um catálogo de tenants centralizado). Antes do primeiro deploy
real em homolog, esse valor precisa refletir o(s) CNPJ(s) que forem efetivamente
provisionados — hoje é uma constante de código, não uma env var; mudar isso é decisão de
produto, registrada aqui só como pendência estrutural (o valor em si foi atualizado pra
`38138785000136` em 2026-09-03, ver commit — trocar a constante hardcoded por uma fonte de
verdade real segue em aberto).

## 8. Deploy (cloudbuild.yaml)

    gcloud builds submit --config cloudbuild.yaml --substitutions=_TAG=$(git rev-parse --short HEAD)

Ordem: build → push → `gcloud run deploy agenda-service`. Sem jobs/migration automáticos
(diferente do optin) — schema é aplicado manualmente antes do primeiro deploy, seção 9.

**Primeiro deploy — sequência (bootstrap da URL):**

1. Rode o `gcloud builds submit` acima com o `_PUBSUB_PUSH_AUDIENCE` placeholder do
   `cloudbuild.yaml` (o serviço sobe, mas os endpoints internos rejeitam qualquer OIDC
   até o passo 3 — não tem problema, nada os chama ainda).
2. `URL=$(gcloud run services describe agenda-service --region southamerica-east1 --format="value(status.url)")`
3. Redeploy só do env var real:

       gcloud run services update agenda-service --region southamerica-east1 \
         --update-env-vars="PUBSUB_PUSH_AUDIENCE=$URL/api/v1/webhooks/agenda/processar"

4. Criar a push subscription e o job do Scheduler (agora que `$URL` existe):

       gcloud pubsub subscriptions create agenda-webhook-inbox-push \
         --topic=agenda-webhook-inbox \
         --push-endpoint="$URL/api/v1/webhooks/agenda/processar" \
         --push-auth-service-account=agenda-run@brikz-ap.iam.gserviceaccount.com \
         --push-auth-token-audience="$URL/api/v1/webhooks/agenda/processar"

       gcloud scheduler jobs create http agenda-varrer-completude \
         --location=southamerica-east1 --schedule="* * * * *" \
         --uri="$URL/api/v1/jobs/varrer-completude" --http-method=POST \
         --oidc-service-account-email=agenda-run@brikz-ap.iam.gserviceaccount.com \
         --oidc-token-audience="$URL/api/v1/webhooks/agenda/processar"

   Note o `--oidc-token-audience` do Scheduler apontando pro MESMO valor de
   `PUBSUB_PUSH_AUDIENCE` (a URL de `/processar`), não pra URL do próprio job
   (`/jobs/varrer-completude`) — `shared/pubsub_auth.py` valida uma única audiência fixa
   pros três endpoints internos, não uma por rota.

Deploys seguintes (imagem já existe, `PUBSUB_PUSH_AUDIENCE` real já no `cloudbuild.yaml`
ou passado via `--substitutions`) voltam a ser um `gcloud builds submit` só.

**Bug achado no primeiro `gcloud builds submit` real (2026-09-03), corrigido antes de
qualquer coisa ficar pra trás:** o separador customizado `^@^` do `--set-env-vars`
(necessário porque `CORS_ALLOWED_ORIGINS` tem vírgulas) quebra porque
`PUBSUB_PUSH_INVOKER_SA` é um e-mail de service account — também tem `@`. O deploy falhou
com `Bad syntax for dict arg`. Trocado pra `^#^` (nenhum valor usado tem `#`). Se algum
valor futuro passar a ter `#`, troque de novo pra outro caractere raro (`gcloud topic
escaping`).

Feito em 2026-09-03: primeiro `gcloud builds submit --substitutions=_TAG=<sha>` →
**SUCCESS**. Serviço `agenda-service` no ar, revisão inicial, URL
`https://agenda-service-6sy5bhymwq-rj.a.run.app`. `PUBSUB_PUSH_AUDIENCE` atualizado via
`gcloud run services update` com a URL real (revisão seguinte) e já propagado de volta pro
`cloudbuild.yaml` (substituição `_PUBSUB_PUSH_AUDIENCE`), então deploys futuros não
regridem pro placeholder.

## 8b. Deploy automático (Cloud Build trigger)

O `optin-service` migrou de remote pessoal para `github.com/brikzai/ap-optin-back` e tem
um trigger configurado (seção 5b do runbook dele) — mesmo padrão replicado aqui.

Repositório registrado sob a MESMA conexão GitHub App do optin (`optin-github`, já
autorizada na org `brikzai` — não precisou de novo consentimento no GitHub):

    gcloud builds repositories create agenda-back --connection=optin-github \
      --region=southamerica-east1 \
      --remote-uri=https://github.com/brikzai/brikzai-ap-consulta-agenda-back.git

Trigger (push na `master` → build + deploy, sem aprovação manual, mesmo molde do
`optin-deploy-master`):

    gcloud builds triggers create github \
      --name=agenda-deploy-master \
      --region=southamerica-east1 \
      --repository=projects/brikz-ap/locations/southamerica-east1/connections/optin-github/repositories/agenda-back \
      --branch-pattern="^master$" \
      --build-config=cloudbuild.yaml \
      --service-account=projects/brikz-ap/serviceAccounts/agenda-build@brikz-ap.iam.gserviceaccount.com \
      --substitutions=_TAG='$SHORT_SHA' \
      --description="Deploy automático do agenda-service a cada push na master"

Feito em 2026-09-03: remote pessoal (`github.com/rdelimasilva/ap-back-consulta-agenda`)
mantido como está; repositório da org criado em `github.com/brikzai/brikzai-ap-consulta-agenda-back`
e adicionado como remote `brikzai` neste checkout. Repositório `agenda-back` e trigger
`agenda-deploy-master` criados (`gcloud builds triggers describe agenda-deploy-master
--region=southamerica-east1`). Verificar o primeiro disparo automático (`gcloud builds list
--region=southamerica-east1 --limit=3`) depois do próximo push na `master` do remote
`brikzai`.

## 9. Onboarding de tenant (banco já existe, criado pelo optin-service)

Pré-requisito: o CNPJ já foi provisionado pelo optin-service (banco `ap_<cnpj>` existe).
Aqui só falta o schema `agenda` (seção 2) e o segredo deste serviço.

1. Rodar os dois comandos SQL da seção 2 (`CREATE SCHEMA`/`ALTER ROLE`) nesse banco.
2. Montar `AGENDA_TENANT_<cnpj>_CONFIG` (arquivo temporário local, nunca pipe triplo —
   mesmo cuidado do runbook do optin: confirme com `gcloud secrets versions list` depois):

       {
         "cloudsql_connection_name": "brikz-ap:southamerica-east1:optin-pg",
         "cloudsql_db_user": "agenda_app",
         "cloudsql_db_password": "<PW_AGENDA_APP>",
         "cloudsql_db_name": "ap_<cnpj>",
         "cerc_client_id": "...",
         "cerc_client_secret": "...",
         "cerc_cnpj_solicitante": "<cnpj>",
         "webhook_basic_user": "...",
         "webhook_basic_password": "..."
       }

       gcloud secrets create AGENDA_TENANT_<cnpj>_CONFIG --data-file=<arquivo> \
         --replication-policy=user-managed --locations=southamerica-east1
       # apagar o arquivo em seguida

3. Aplicar o schema SQL deste serviço nesse banco (`CLOUDSQL_*` do `.env` local apontando
   pra `agenda_app`/`ap_<cnpj>`, não pro segredo do tenant — mesmo padrão do
   `ap-back-contratos`, aplicação de schema é manual):

       python scripts/apply_schema.py sql/schema/01-agenda-schema.sql
       python scripts/apply_schema.py sql/schema/02-agenda-schema-fixes.sql
       python scripts/apply_schema.py sql/schema/03-agenda-ur-evento.sql
       python scripts/apply_schema.py sql/schema/04-agenda-ur-evento-fixes.sql
       python scripts/apply_schema.py sql/schema/05-agenda-ur-sequencia.sql

4. Adicionar o CNPJ em `_TENANTS_JOBS_PERIODICOS` (seção 7) se os jobs periódicos
   devem cobrir esse tenant, e redeployar.

Feito em 2026-09-03 (tenant `38138785000136`, único hoje): `AGENDA_TENANT_38138785000136_CONFIG`
criado (9 chaves) — `cerc_client_id`/`cerc_client_secret`/`cerc_cnpj_solicitante` **reaproveitados
do segredo `TENANT_38138785000136_CONFIG` do optin-service** (decisão explícita, diverge do
design doc "credenciais OAuth2 próprias por serviço" — CERC ainda não emitiu credencial
específica pro agenda-service; trocar quando existir). `webhook_basic_user`/
`webhook_basic_password` gerados novos, só pra este serviço. Verificado com `gcloud secrets
versions list` sem expor valores.

## 10. Smoke test pós-deploy

    URL=$(gcloud run services describe agenda-service --region southamerica-east1 --format="value(status.url)")
    curl -s -w "\n%{http_code}\n" "$URL/api/v1/health"                              # 200
    curl -s -w "\n%{http_code}\n" "$URL/api/v1/agendas/urs"                         # 401 (sem JWT, da aplicação)
    curl -s -w "\n%{http_code}\n" -H "Authorization: Bearer $TOKEN" "$URL/api/v1/agendas/urs"  # 200

    # Pub/Sub: publica uma mensagem de teste e confere que o consumidor rejeita sem OIDC
    # (curl -X POST sem -d não manda Content-Length e o front-end do Cloud Run devolve
    # 411 antes de chegar na aplicação — sempre passe -d '' num POST sem corpo)
    curl -s -o /dev/null -w "%{http_code}\n" -X POST -d '' "$URL/api/v1/webhooks/agenda/processar"   # 401 (sem OIDC)

    # Scheduler: dispara o job manualmente e confere execução
    gcloud scheduler jobs run agenda-varrer-completude --location=southamerica-east1
    gcloud scheduler jobs describe agenda-varrer-completude --location=southamerica-east1

`$TOKEN` gerado com o mesmo mecanismo que o optin-service usa para esse tenant
(`gerar_jwt.py` do repositório do optin, chave privada dele — este serviço não tem
gerador próprio, só validador).

> Desde o endurecimento do `jwt_auth` (PR seguranca/jwt-auth-endurecido), tokens desta chave
> local só são aceitos com `IAM_JWT_ACEITAR_CHAVE_HOMOLOG=true` e `ENVIRONMENT` != `production`;
> o token sai com `type=access` e `sub` (obrigatórios). O front real usa o IAM (`IAM_JWT_PUBLIC_KEY_BRIKZ_IAM`).

Feito em 2026-09-03: `/health` 200; `/agendas/urs` sem JWT → 401 `NAO_AUTENTICADO` (da
aplicação); `/agendas/urs` com JWT do tenant 38138785000136 → 200 (`{"urs": [],
"proximoCursor": null}`, tenant recém-provisionado pro agenda-service, mesmo sem dados
ingeridos ainda); `/webhooks/agenda/processar` e `/jobs/varrer-completude` sem OIDC → 401
`OIDC inválido` (da aplicação, depois de corrigir o `-d ''` acima — sem isso vinha `411` do
front-end do Cloud Run, não da app). Scheduler: primeiro tick automático (segundos após a
criação do job) → `401` (propagação de IAM/OIDC ainda não tinha completado, mesmo
comportamento já visto no runbook do optin); disparo manual ~1min depois e tick automático
seguinte → `200`.

## 11. Teste real contra a CERC (2026-09-03) — 4 bugs achados e corrigidos

Primeiro `POST /api/v1/agendas/consultas` (modo ONLINE) contra a CERC de homologação
real, UFR `15076963000146`, credenciadoras `72253725000100`/`09700540000152`/
`49240077000128`, arranjos `["99T"]`. Nenhum dos quatro problemas abaixo apareceria
rodando só os testes unitários (todos usam `respx` com corpo mockado no formato que a
SPEC03 documenta) — só a chamada real contra a CERC de verdade expôs.

Pré-requisito descoberto no caminho: a validação A10 (fail-closed) exige uma
`politica_consulta` ativa pro `motivo` usado — criada via `PUT /api/v1/config/politicas-consulta`
antes do teste (tenant recém-provisionado não tem nenhuma).

1. **OAuth2 via corpo, não Basic Auth.** `services/cerc/token_provider.py` mandava
   `client_id`/`client_secret` como parâmetros do corpo do POST; a CERC exige HTTP Basic
   Auth (RFC 6749 §2.3.1) e respondia `401` sem mais detalhe — `optin-service` já fazia
   isso certo (`auth=(client_id, client_secret)` no httpx), esta cópia divergiu. Corrigido
   + teste novo (`test_fetch_token_usa_basic_auth_nao_body`) que verifica o header
   `Authorization: Basic` e que client_id/secret não vazam pro corpo.
2. **Resposta embrulhada, não array puro.** SPEC03 §4.3 documenta `200` como array de
   agendas; a CERC de homologação devolve `{"agendas": [...], "protocoloRequisicao": ...,
   "indicadoresConsistencia": [...], "documentoUsuarioFinalRecebedor": ...}`. Corrigido em
   `_chamar_cerc` (aceita os dois formatos).
3. **`documentoUsuarioFinalRecebedor` no envelope, não por item.** Consequência do achado
   2: esse campo vem uma vez no objeto de fora, não repetido em cada item de `agendas`
   como `_traduzir_ur` esperava (`KeyError`, 2652 URs foram pra `agenda_ur_rejeitada` antes
   do fix). Corrigido propagando o valor do envelope pra cada item antes de devolver.
4. **`dataHoraUltimaAtualizacao` ausente na resposta síncrona real.** SPEC03 §4.3
   documenta esse campo por titular; a CERC de homologação simplesmente não o manda na
   resposta síncrona (mais 1326 URs rejeitadas até esse fix). Corrigido com fallback pra
   `datetime.now(timezone.utc)` quando ausente — semanticamente correto: é uma consulta
   síncrona, "agora" é o dado mais fresco que temos. Teste novo
   (`test_consultar_agenda_sem_data_hora_ultima_atualizacao_usa_agora`).

**Achado de infra, não de API:** o `Dockerfile` deste serviço nunca passava `--timeout`
pro gunicorn (default 30s) nem usava `${WEB_CONCURRENCY:-2}` pros workers — divergiu do
`Dockerfile` do optin, que já faz os dois certo. Com 1326 URs inseridas uma a uma na mesma
requisição síncrona (nenhuma escrita em lote — mesma decisão consciente "não otimizar
antes de medir" do design doc §15), o worker do gunicorn matava a requisição no meio antes
mesmo do timeout de 60s do Cloud Run (`cloudbuild.yaml`) entrar em ação. Corrigido pra
`--timeout 60` (mesmo valor do Cloud Run, mesmo padrão do optin). Uma consulta ONLINE
desse tamanho (todas as credenciadoras, ~8 meses, `"99T"`) ainda é lenta o bastante pra
chegar perto do limite de 60s — se isso vier a ser um padrão de uso real (não só teste),
revisitar a escrita em lote de `upsert_agenda_ur` é candidato natural, mas não foi feito
aqui (fora de escopo desta verificação).

**Resultado final, com os 5 fixes acima (4 de API + 1 de infra) e o Dockerfile já revertido
pro timeout de produção (60s):** consulta `01M1MQ52GFJ9WD68C400VMH5EH` fechada como
`PARCIAL` (correto — ONLINE), **1326 URs reais persistidas** (`contagemPorOrigem.SINCRONO
= 1326`), confirmado via `GET /agendas/consultas/{id}`, `GET /agendas/urs` e `GET
/agendas/urs/posicao` (retornou posição agregada real: ~R$6,58M constituídos, segregado
por credenciadora e por arranjo, `valorFumaca` sempre à parte). O deploy que rodou esse
teste específico usou timeouts temporariamente esticados (Cloud Run e gunicorn a 300s) só
pra essa verificação única; o deploy final já está de volta em 60s.

**Pendência que sobrou:** as credenciais CERC seguem emprestadas do optin-service (ponto
já registrado na seção 9) — funcionaram para autenticar e consultar, mas a CERC pode vir a
diferenciar por produto/serviço no futuro; trocar quando existir credencial própria pro
agenda-service.

**agenda-service em homolog está no ar e servindo tráfego real:**
`https://agenda-service-6sy5bhymwq-rj.a.run.app`

## 12. Cadastro do canal de webhook na CERC (2026-09-04/05) — 3 bugs achados e corrigidos

Testando o cadastro real do canal de webhook (`tipoEvento=agenda`) no portal de homologação
da CERC, 3 problemas reais, nenhum pego pelos testes unitários (que mockam o formato
documentado na SPEC, que diverge do real):

1. **Header de auth mal formado no canal.** O campo "Header" do portal da CERC é texto livre
   (`Nome, Valor`), não usuário/senha separados — foi preenchido só com a senha crua
   (`basic <senha>`), sem usuário nem Base64. Corrigido: valor certo é
   `Authorization, Basic base64(usuario:senha)`. Sintoma: `401`, log de diagnóstico mostrava
   "sem Basic Auth — esquema recebido: (ausente)" (a CERC nem mandava header reconhecível).
2. **Envelope embrulhado em array.** SPEC03 §5.2 documenta objeto solto; a CERC manda
   `[{...}]`. Corrigido em `webhook_agenda` (aceita os dois formatos).
3. **`tipoEvento=testeCerc` sem o campo `evento`.** É o ping de conectividade (SPEC01 §4.4)
   — não carrega UR real. Corrigido: só exige `dataHoraEvento` nesse caso; `agenda` e demais
   tipos continuam exigindo os três campos.

Os 3 foram achados com log de diagnóstico temporário (nunca logou senha, só forma do header
e corpo bruto do evento). O que está e o que não está confirmado:

- **Bug 1 (auth):** confirmado ponta a ponta — depois de corrigir o header no portal, a
  requisição da CERC passou a autenticar (deixou de dar `401`).
- **Bugs 2 e 3 (array + `testeCerc` sem `evento`):** o formato real foi observado no corpo
  bruto logado da requisição que a CERC mandou; os fixes foram validados só com `curl`
  reproduzindo esse corpo (`202`). **Não** houve confirmação com uma requisição nova vinda
  do portal da CERC depois do deploy dos fixes — ver pendência abaixo.
- **Logs de diagnóstico:** o do header de auth foi removido junto com o fix; o do corpo bruto
  (`[Webhook][diag2]`) ficou no código por mais um ciclo e foi removido em 2026-09-05, sem
  a confirmação ponta a ponta que motivava mantê-lo. Se a pendência abaixo exigir novo
  diagnóstico, reintroduzir só o log do corpo bruto (nunca credenciais), e remover de novo.

**Pendência aberta, não resolvida:** depois dos 3 fixes acima, o botão "testar webhook" do
portal da CERC continuou reportando `400` (o mesmo erro de antes do fix). Confirmado
repetidas vezes, inclusive em aba anônima, que **nenhuma requisição nova chega no nosso
servidor** quando esse botão é clicado (log do Cloud Run sem nenhum hit em
`/webhooks/agenda/` nos minutos seguintes ao clique) — testado diretamente com `curl`
simulando o payload real, sempre `202`. Hipótese mais provável: o botão de teste do portal
da CERC reexibe o resultado da primeira tentativa (de antes dos fixes) em vez de refazer a
chamada. Repassado pra CERC com essa evidência.

**Teste alternativo (consulta online real, dispara o webhook de verdade por trás):**
tentativa em 2026-09-05 ~21h (horário local) devolveu `105998 FORA DA JANELA DE
PROCESSAMENTO` — CERC de homologação não processa consulta online fora do horário comercial.
Repetir em horário comercial (dia útil) e conferir se `webhook_inbox` recebe o evento real
(`tipoEvento=agenda`) dessa vez.
