import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import JsonResponse
from django.test import RequestFactory


@pytest.fixture(scope="module")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(autouse=True)
def _set_env(monkeypatch, keypair):
    _, public_pem = keypair
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY", public_pem)
    monkeypatch.setenv("IAM_JWT_ISSUER", "brikz-iam")


def _token(private_pem, **overrides):
    payload = {
        "exp": int(time.time()) + 300,
        "iss": "brikz-iam",
        "sub": "user-1",
        "financiador_id": "12345678000199",
    }
    payload.update(overrides)
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def test_validar_bearer_token_aceita_token_valido(keypair):
    from shared.jwt_auth import validar_bearer_token

    private_pem, _ = keypair
    claims = validar_bearer_token(f"Bearer {_token(private_pem)}")
    assert claims["sub"] == "user-1"


def test_validar_bearer_token_rejeita_token_expirado(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    private_pem, _ = keypair
    expirado = _token(private_pem, exp=int(time.time()) - 10)
    with pytest.raises(JwtAuthError):
        validar_bearer_token(f"Bearer {expirado}")


def test_validar_bearer_token_rejeita_issuer_incorreto(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    private_pem, _ = keypair
    outro_issuer = _token(private_pem, iss="outro-idp")
    with pytest.raises(JwtAuthError):
        validar_bearer_token(f"Bearer {outro_issuer}")


def test_validar_bearer_token_rejeita_header_ausente():
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    with pytest.raises(JwtAuthError):
        validar_bearer_token("")


def test_validar_bearer_token_rejeita_sem_esquema_bearer(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    private_pem, _ = keypair
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_token(private_pem))


def test_jwt_required_retorna_401_sem_header():
    from shared.jwt_auth import jwt_required

    @jwt_required
    def view(request):
        return JsonResponse({"ok": True})

    request = RequestFactory().get("/api/v1/agendas/urs")
    response = view(request)
    assert response.status_code == 401


def test_jwt_required_popula_claims_e_financiador_id_quando_valido(keypair):
    from shared.jwt_auth import jwt_required

    private_pem, _ = keypair
    token = _token(private_pem)

    @jwt_required
    def view(request):
        return JsonResponse({"sub": request.jwt_claims["sub"], "financiador_id": request.financiador_id})

    request = RequestFactory().get("/api/v1/agendas/urs", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = view(request)
    assert response.status_code == 200
    assert json.loads(response.content) == {"sub": "user-1", "financiador_id": "12345678000199"}


def test_jwt_required_retorna_401_sem_claim_financiador_id(keypair):
    from shared.jwt_auth import jwt_required

    private_pem, _ = keypair
    token = pyjwt.encode(
        {"exp": int(time.time()) + 300, "iss": "brikz-iam", "sub": "user-1"}, private_pem, algorithm="RS256"
    )

    @jwt_required
    def view(request):
        return JsonResponse({"ok": True})

    request = RequestFactory().get("/api/v1/agendas/urs", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = view(request)
    assert response.status_code == 401


def test_jwt_required_retorna_401_com_financiador_id_mal_formatado(keypair):
    from shared.jwt_auth import jwt_required

    private_pem, _ = keypair
    token = _token(private_pem, financiador_id="abc123")

    @jwt_required
    def view(request):
        return JsonResponse({"ok": True})

    request = RequestFactory().get("/api/v1/agendas/urs", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = view(request)
    assert response.status_code == 401


# --- Segunda chave pública (brikz-iam), aceita além da de homolog ---------

def _novo_par_rsa():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def segunda_chave(monkeypatch, keypair):
    private_pem, public_pem = _novo_par_rsa()
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", public_pem)
    return private_pem


def test_aceita_token_assinado_pela_segunda_chave(segunda_chave):
    from shared.jwt_auth import validar_bearer_token

    claims = validar_bearer_token(f"Bearer {_token(segunda_chave)}")
    assert claims["financiador_id"] == "12345678000199"


def test_segunda_chave_configurada_nao_quebra_token_da_primeira(segunda_chave, keypair):
    from shared.jwt_auth import validar_bearer_token

    claims = validar_bearer_token(f"Bearer {_token(keypair[0])}")
    assert claims["financiador_id"] == "12345678000199"


def test_jwt_required_aceita_token_da_segunda_chave(segunda_chave):
    from shared.jwt_auth import jwt_required

    @jwt_required
    def view(request):
        return JsonResponse({"financiador_id": request.financiador_id})

    token = _token(segunda_chave)
    response = view(RequestFactory().get("/x", HTTP_AUTHORIZATION=f"Bearer {token}"))
    assert response.status_code == 200
    assert json.loads(response.content) == {"financiador_id": "12345678000199"}


def test_rejeita_token_assinado_por_terceira_chave(segunda_chave):
    from shared.jwt_auth import jwt_required

    terceira_priv, _ = _novo_par_rsa()

    @jwt_required
    def view(request):
        return JsonResponse({"ok": True})

    token = _token(terceira_priv)
    response = view(RequestFactory().get("/x", HTTP_AUTHORIZATION=f"Bearer {token}"))
    assert response.status_code == 401


def test_token_expirado_da_segunda_chave_diz_expirado(segunda_chave):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    expirado = _token(segunda_chave, exp=int(time.time()) - 10)
    with pytest.raises(JwtAuthError, match="expirado"):
        validar_bearer_token(f"Bearer {expirado}")


def test_sem_env_da_segunda_chave_token_dela_e_invalido(monkeypatch, keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    monkeypatch.delenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", raising=False)
    privada, _ = _novo_par_rsa()
    with pytest.raises(JwtAuthError, match="inválido"):
        validar_bearer_token(f"Bearer {_token(privada)}")


def test_env_vazia_da_segunda_chave_e_ignorada(monkeypatch, keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", "")
    privada, _ = _novo_par_rsa()
    with pytest.raises(JwtAuthError, match="inválido"):
        validar_bearer_token(f"Bearer {_token(privada)}")
