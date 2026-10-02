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

Multi-tenancy: exige o claim `financiador_id` (CNPJ, 14 dígitos) em todo
JWT válido e o expõe em `request.financiador_id`, além de
`request.jwt_claims`.
"""
import functools
import os
import re

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


def validar_bearer_token(authorization_header: str) -> dict:
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise JwtAuthError("header Authorization ausente ou sem esquema Bearer")

    token = authorization_header[len("Bearer "):].strip()
    if not token:
        raise JwtAuthError("token vazio")

    chaves = _public_keys()
    issuer = os.environ["IAM_JWT_ISSUER"]
    try:
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

        financiador_id = claims.get("financiador_id")
        if not financiador_id or not re.fullmatch(r"\d{14}", str(financiador_id)):
            return JsonResponse(
                {"erro": "NAO_AUTENTICADO", "mensagem": "claim financiador_id ausente ou inválido"}, status=401
            )

        request.jwt_claims = claims
        request.financiador_id = financiador_id
        return view_func(request, *args, **kwargs)

    return wrapper
