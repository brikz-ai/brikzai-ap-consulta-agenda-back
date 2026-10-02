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
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", public_pem)
    monkeypatch.setenv("IAM_JWT_ISSUER", "brikz-iam")


def _token(private_pem, **overrides):
    payload = {
        "exp": int(time.time()) + 300,
        "iss": "brikz-iam", "type": "access",
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
        {"exp": int(time.time()) + 300, "iss": "brikz-iam", "type": "access", "sub": "user-1"}, private_pem, algorithm="RS256"
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


# --- Chaves aceitas: IAM real, lista de rotação e homolog com opt-in ------
#
# IAM_JWT_PUBLIC_KEY_BRIKZ_IAM é a chave do IAM real (fixture base acima).
# IAM_JWT_PUBLIC_KEY é a chave LOCAL de homolog (gerar_jwt.py): só vale com
# IAM_JWT_ACEITAR_CHAVE_HOMOLOG=true e ENVIRONMENT != production.

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
def chave_homolog(monkeypatch, keypair):
    private_pem, public_pem = _novo_par_rsa()
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY", public_pem)
    monkeypatch.delenv("IAM_JWT_ACEITAR_CHAVE_HOMOLOG", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    return private_pem


def _view_ok():
    from shared.jwt_auth import jwt_required

    @jwt_required
    def view(request):
        return JsonResponse({"financiador_id": request.financiador_id})

    return view


def test_refresh_token_e_rejeitado(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    with pytest.raises(JwtAuthError, match="access"):
        validar_bearer_token(f"Bearer {_token(keypair[0], type='refresh')}")


def test_token_sem_type_e_rejeitado(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    claims = {k: v for k, v in pyjwt.decode(
        _token(keypair[0]), options={"verify_signature": False}).items() if k != "type"}
    token = pyjwt.encode(claims, keypair[0], algorithm="RS256")
    with pytest.raises(JwtAuthError):
        validar_bearer_token(f"Bearer {token}")


def test_token_sem_sub_e_rejeitado(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    claims = {k: v for k, v in pyjwt.decode(
        _token(keypair[0]), options={"verify_signature": False}).items() if k != "sub"}
    token = pyjwt.encode(claims, keypair[0], algorithm="RS256")
    with pytest.raises(JwtAuthError):
        validar_bearer_token(f"Bearer {token}")


def test_token_com_sub_vazio_e_rejeitado(keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    with pytest.raises(JwtAuthError, match="sub"):
        validar_bearer_token(f"Bearer {_token(keypair[0], sub='  ')}")


def test_jwt_required_devolve_401_para_refresh_token(keypair):
    token = _token(keypair[0], type="refresh")
    response = _view_ok()(RequestFactory().get("/x", HTTP_AUTHORIZATION=f"Bearer {token}"))
    assert response.status_code == 401


def test_chave_homolog_rejeitada_sem_opt_in(chave_homolog):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    with pytest.raises(JwtAuthError):
        validar_bearer_token(f"Bearer {_token(chave_homolog)}")


def test_chave_homolog_aceita_com_opt_in_fora_de_producao(chave_homolog, monkeypatch):
    from shared.jwt_auth import validar_bearer_token

    monkeypatch.setenv("IAM_JWT_ACEITAR_CHAVE_HOMOLOG", "true")
    monkeypatch.setenv("ENVIRONMENT", "homolog")
    claims = validar_bearer_token(f"Bearer {_token(chave_homolog)}")
    assert claims["financiador_id"] == "12345678000199"


def test_chave_homolog_rejeitada_em_producao_mesmo_com_opt_in(chave_homolog, monkeypatch):
    monkeypatch.setenv("IAM_JWT_ACEITAR_CHAVE_HOMOLOG", "true")
    monkeypatch.setenv("ENVIRONMENT", "production")
    token = _token(chave_homolog)
    response = _view_ok()(RequestFactory().get("/x", HTTP_AUTHORIZATION=f"Bearer {token}"))
    assert response.status_code == 401


def test_chave_do_iam_continua_aceita_com_homolog_configurada(chave_homolog, keypair):
    from shared.jwt_auth import validar_bearer_token

    claims = validar_bearer_token(f"Bearer {_token(keypair[0])}")
    assert claims["financiador_id"] == "12345678000199"


def test_lista_de_chaves_aceita_qualquer_uma_para_rotacao(monkeypatch, keypair):
    from shared.jwt_auth import validar_bearer_token

    antiga_priv, antiga_pub = _novo_par_rsa()
    nova_priv, nova_pub = _novo_par_rsa()
    # Formato do Secret Manager: PEM concatenadas numa linha, \n literais.
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEYS", (antiga_pub + nova_pub).replace("\n", "\\n"))
    monkeypatch.delenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", raising=False)
    for privada in (antiga_priv, nova_priv):
        claims = validar_bearer_token(f"Bearer {_token(privada)}")
        assert claims["financiador_id"] == "12345678000199"


def test_rejeita_token_assinado_por_chave_desconhecida(keypair):
    terceira_priv, _ = _novo_par_rsa()
    token = _token(terceira_priv)
    response = _view_ok()(RequestFactory().get("/x", HTTP_AUTHORIZATION=f"Bearer {token}"))
    assert response.status_code == 401


def test_token_expirado_de_outra_chave_da_lista_diz_expirado(monkeypatch, keypair):
    from shared.jwt_auth import JwtAuthError, validar_bearer_token

    nova_priv, nova_pub = _novo_par_rsa()
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEYS", nova_pub)
    expirado = _token(nova_priv, exp=int(time.time()) - 10)
    with pytest.raises(JwtAuthError, match="expirado"):
        validar_bearer_token(f"Bearer {expirado}")


def test_sem_nenhuma_chave_configurada_levanta_keyerror(monkeypatch, keypair):
    from shared.jwt_auth import validar_bearer_token

    for nome in ("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", "IAM_JWT_PUBLIC_KEYS", "IAM_JWT_PUBLIC_KEY"):
        monkeypatch.delenv(nome, raising=False)
    with pytest.raises(KeyError):
        validar_bearer_token(f"Bearer {_token(keypair[0])}")
