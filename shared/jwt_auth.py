"""Autenticação Bearer JWT do IdP corporativo (design doc §3.3).

Chaves públicas RS256 fixas e emissor esperado (IAM_JWT_ISSUER) — sem
JWKS/rede, mesmo padrão de shared/secrets.py para
segredos estáticos. Rotas isentas (health, push do Pub/Sub) simplesmente
não usam @jwt_required — não há middleware global com exceção por path.

Quais chaves são aceitas (ver _public_keys):
- IAM_JWT_PUBLIC_KEY_BRIKZ_IAM: a chave do IAM real (brikz-ai/backend,
  services/iam — login único do ap-front).
- IAM_JWT_PUBLIC_KEYS (opcional): várias PEM concatenadas, para a rotação da
  chave do IAM (antiga + nova durante a janela de troca).
- IAM_JWT_PUBLIC_KEY: apesar do nome, é a chave LOCAL de homolog, gerada por
  scripts/gerar_chaves_jwt.py do ap-optin-back e usada por gerar_jwt.py para
  emitir tokens de teste com iss=brikz-iam. Só é aceita com
  IAM_JWT_ACEITAR_CHAVE_HOMOLOG=true e ENVIRONMENT != production.

Além da assinatura, exp e iss, todo token precisa de `sub` não vazio e
`type == "access"` — o IAM assina access e refresh com a mesma chave e o
mesmo iss, então sem checar `type` um refresh token (14 dias) passaria como
access token (30 min).

Keycloak (transição IAM → Keycloak): com KEYCLOAK_AP_ISSUER configurada
(https://auth.brikz.ai/realms/ap), aceita também os tokens do realm ap do
Keycloak, emitidos para o client público ap-console do ap-front. O token
vai para o Keycloak ou para o IAM pelo `iss` (ainda não verificado — só
escolhe o caminho; a assinatura de cada caminho só fecha com as chaves
daquele emissor). No Keycloak as chaves vêm da JWKS do realm (rede, com
cache em memória) e, além de exp/iss/sub/type, o `aud` precisa conter
KEYCLOAK_AP_AUDIENCE (padrão ap-console). Sem KEYCLOAK_AP_ISSUER, só o IAM.

Multi-tenancy: exige o claim `financiador_id` (CNPJ, 14 dígitos) em todo
JWT válido e o expõe em `request.financiador_id`, além de
`request.jwt_claims`.
"""
import functools
import json
import os
import re
import threading
import time
import urllib.request

import jwt
from django.http import JsonResponse


class JwtAuthError(Exception):
    def __init__(self, mensagem: str):
        self.mensagem = mensagem
        super().__init__(mensagem)


def _desescapar(pem: str) -> str:
    # Secret Manager/.env guardam a PEM numa linha só, com \n literais.
    return pem.replace("\\n", "\n").strip()


def _separar_pems(valor: str) -> list[str]:
    """IAM_JWT_PUBLIC_KEYS traz várias PEM concatenadas (rotação da chave do
    IAM): cada bloco BEGIN/END vira uma chave."""
    return re.findall(
        r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", _desescapar(valor), flags=re.DOTALL
    )


def _chave_homolog_permitida() -> bool:
    """A chave de homolog (IAM_JWT_PUBLIC_KEY) tem a privada fora do IAM, na
    máquina de quem emite tokens de teste — quem a tem forja qualquer
    financiador. Fail-closed: só vale com opt-in explícito E fora de
    produção. Não dá para confiar só em ENVIRONMENT: o deploy do Cloud Run
    hoje roda com ENVIRONMENT=homolog e atende o front real (ap.brikz.ai)."""
    ambiente = os.getenv("ENVIRONMENT", "development").strip().lower()
    flag = os.getenv("IAM_JWT_ACEITAR_CHAVE_HOMOLOG", "").strip().lower() == "true"
    return flag and ambiente != "production"


def _public_keys() -> list[str]:
    """Chaves públicas aceitas, em ordem: as do IAM real (IAM_JWT_PUBLIC_KEYS
    e IAM_JWT_PUBLIC_KEY_BRIKZ_IAM) e, só com opt-in fora de produção, a de
    homolog (IAM_JWT_PUBLIC_KEY). Nenhuma configurada levanta KeyError — o
    mesmo sinal de "serviço mal configurado" que a env var ausente já dava."""
    chaves = []
    lista = os.environ.get("IAM_JWT_PUBLIC_KEYS")
    if lista:
        chaves.extend(_separar_pems(lista))
    brikz_iam = os.environ.get("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM")
    if brikz_iam:
        chaves.append(_desescapar(brikz_iam))
    homolog = os.environ.get("IAM_JWT_PUBLIC_KEY")
    if homolog and _chave_homolog_permitida():
        chaves.append(_desescapar(homolog))
    if not chaves:
        raise KeyError("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM")
    return chaves


def _validar_claims_de_acesso(claims: dict) -> dict:
    """sub identifica quem chamou (auditoria) e type separa access de
    refresh — os dois saem do mesmo IAM, com a mesma chave e o mesmo iss."""
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise JwtAuthError("claim sub ausente ou vazio")
    if claims.get("type") != "access":
        raise JwtAuthError("token não é de acesso (claim type deve ser 'access')")
    return claims


class IdpIndisponivel(Exception):
    """JWKS do Keycloak inacessível e sem cópia em cache — não dá para dizer
    se o token é válido. Vira 503, não 401: o cliente não errou."""


# Cache da JWKS por URL: (instante da busca, JWKS). Uma hora basta — o
# Keycloak publica a chave nova antes de passar a assinar com ela, e um kid
# desconhecido força nova busca (ver _chave_keycloak).
_JWKS_TTL_SEGUNDOS = 3600
# Nova busca forçada por kid desconhecido no máximo a cada 30 s: token com kid
# inventado não vira martelada na JWKS do Keycloak.
_JWKS_INTERVALO_MINIMO_SEGUNDOS = 30
_jwks_cache: dict = {}
_jwks_lock = threading.Lock()


def _keycloak_issuer():
    issuer = os.getenv("KEYCLOAK_AP_ISSUER", "").strip().rstrip("/")
    return issuer or None


def _keycloak_audience() -> str:
    return os.getenv("KEYCLOAK_AP_AUDIENCE", "").strip() or "ap-console"


def _baixar_jwks(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resposta:
        return json.loads(resposta.read().decode("utf-8"))


def _jwks(issuer: str, forcar: bool = False) -> dict:
    url = f"{issuer}/protocol/openid-connect/certs"
    agora = time.monotonic()
    with _jwks_lock:
        em_cache = _jwks_cache.get(url)
        if em_cache:
            idade = agora - em_cache[0]
            limite = _JWKS_INTERVALO_MINIMO_SEGUNDOS if forcar else _JWKS_TTL_SEGUNDOS
            if idade < limite:
                return em_cache[1]
        try:
            jwks = _baixar_jwks(url)
        except (OSError, ValueError) as exc:
            if em_cache:
                # Keycloak fora do ar (scale-to-zero subindo, rede): a cópia
                # antiga continua valendo até ele voltar.
                return em_cache[1]
            raise IdpIndisponivel(f"JWKS do Keycloak inacessível: {exc}") from exc
        _jwks_cache[url] = (agora, jwks)
        return jwks


def _chave_keycloak(issuer: str, kid):
    # A JWKS do realm também traz a chave de cifragem (use=enc, RSA-OAEP):
    # só a de assinatura RSA serve aqui.
    for forcar in (False, True):
        for jwk in _jwks(issuer, forcar).get("keys", []):
            if jwk.get("kid") == kid and jwk.get("kty") == "RSA" and jwk.get("use", "sig") == "sig":
                return jwt.PyJWK(jwk, algorithm="RS256").key
    raise JwtAuthError("chave do token (kid) não encontrada na JWKS do Keycloak")


def _validar_token_keycloak(token: str, issuer: str) -> dict:
    chave = _chave_keycloak(issuer, jwt.get_unverified_header(token).get("kid"))
    claims = jwt.decode(
        token,
        chave,
        algorithms=["RS256"],
        issuer=issuer,
        audience=_keycloak_audience(),
        options={"require": ["exp", "iss", "sub", "aud"]},
    )
    return _validar_claims_de_acesso(claims)


def _emissor_do_token(token: str):
    """iss sem verificar a assinatura — só escolhe entre Keycloak e IAM."""
    return jwt.decode(token, options={"verify_signature": False}).get("iss")


def validar_bearer_token(authorization_header: str) -> dict:
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise JwtAuthError("header Authorization ausente ou sem esquema Bearer")

    token = authorization_header[len("Bearer "):].strip()
    if not token:
        raise JwtAuthError("token vazio")

    try:
        issuer_keycloak = _keycloak_issuer()
        if issuer_keycloak and _emissor_do_token(token) == issuer_keycloak:
            return _validar_token_keycloak(token, issuer_keycloak)

        chaves = _public_keys()
        issuer = os.environ["IAM_JWT_ISSUER"]
        for i, chave in enumerate(chaves):
            try:
                claims = jwt.decode(
                    token,
                    chave,
                    algorithms=["RS256"],
                    issuer=issuer,
                    options={"require": ["exp", "iss", "sub"]},
                )
            except jwt.InvalidSignatureError:
                # Só a assinatura inválida tenta a próxima chave; qualquer outra
                # falha (expirado, issuer errado...) segue o fluxo normal.
                if i == len(chaves) - 1:
                    raise
                continue
            return _validar_claims_de_acesso(claims)
    except jwt.ExpiredSignatureError:
        raise JwtAuthError("token expirado")
    except jwt.InvalidTokenError as exc:
        raise JwtAuthError(f"token inválido: {exc}")


def jwt_required(view_func):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            claims = validar_bearer_token(request.headers.get("Authorization", ""))
        except JwtAuthError as exc:
            return JsonResponse({"erro": "NAO_AUTENTICADO", "mensagem": exc.mensagem}, status=401)
        except IdpIndisponivel:
            # Keycloak inacessível e JWKS fora do cache: o token pode até ser
            # bom, só não dá para conferir agora.
            return JsonResponse({"erro": "IDP_INDISPONIVEL"}, status=503)

        financiador_id = claims.get("financiador_id")
        if not financiador_id or not re.fullmatch(r"\d{14}", str(financiador_id)):
            return JsonResponse(
                {"erro": "NAO_AUTENTICADO", "mensagem": "claim financiador_id ausente ou inválido"}, status=401
            )

        request.jwt_claims = claims
        # str() de propósito: um IdP que emita o claim como número JSON (não
        # string) passa no fullmatch acima (que já compara contra str()), mas
        # sem esta conversão o valor cru (int) ficaria em request.financiador_id
        # e o CNPJ não casaria com o tenant nem com o financiador da URL.
        request.financiador_id = str(financiador_id)
        return view_func(request, *args, **kwargs)

    return wrapper
