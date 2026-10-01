"""Autenticação Bearer JWT do IdP corporativo (design doc §3.3).

Chave pública RS256 fixa (IAM_JWT_PUBLIC_KEY, mais a opcional
IAM_JWT_PUBLIC_KEY_BRIKZ_IAM) e emissor esperado
(IAM_JWT_ISSUER) — sem JWKS/rede, mesmo padrão de shared/secrets.py para
segredos estáticos. Rotas isentas (health, push do Pub/Sub) simplesmente
não usam @jwt_required — não há middleware global com exceção por path.

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


def _public_keys() -> list[str]:
    """Chaves públicas aceitas, em ordem: a de homolog (obrigatória) e, se
    configurada, a do brikz-iam (IAM_JWT_PUBLIC_KEY_BRIKZ_IAM, login único)."""
    chaves = [os.environ["IAM_JWT_PUBLIC_KEY"].replace("\\n", "\n")]
    segunda = os.environ.get("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM")
    if segunda:
        chaves.append(segunda.replace("\\n", "\n"))
    return chaves


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
                return jwt.decode(
                    token,
                    chave,
                    algorithms=["RS256"],
                    issuer=issuer,
                    options={"require": ["exp", "iss"]},
                )
            except jwt.InvalidSignatureError:
                # Só a assinatura inválida tenta a próxima chave; qualquer outra
                # falha (expirado, issuer errado...) segue o fluxo normal.
                if i == len(chaves) - 1:
                    raise
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
