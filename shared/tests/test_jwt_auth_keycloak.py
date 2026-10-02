"""Testes dos tokens do Keycloak (realm ap) no jwt_auth. Par RSA gerado em
memória e JWKS falsa (_baixar_jwks substituída): sem rede, sem banco."""
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import JsonResponse
from django.test import RequestFactory

from shared import jwt_auth
from shared.jwt_auth import IdpIndisponivel, JwtAuthError, jwt_required, validar_bearer_token

ISSUER_KC = "https://auth.brikz.ai/realms/ap"
ISSUER_IAM = "brikz-iam"
FINANCIADOR = "38138785000136"
KID = "kid-teste"


def _gerar_par():
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privada = chave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return chave, privada


def _jwk(chave, kid=KID, use="sig"):
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(chave.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": use, "alg": "RS256" if use == "sig" else "RSA-OAEP"})
    return jwk


class JwksFalsa:
    """Substitui _baixar_jwks: devolve a JWKS atual e conta as buscas."""

    def __init__(self, jwks):
        self.jwks = jwks
        self.buscas = 0
        self.falhar = False

    def __call__(self, url):
        assert url == f"{ISSUER_KC}/protocol/openid-connect/certs"
        self.buscas += 1
        if self.falhar:
            raise OSError("conexão recusada")
        return self.jwks


@pytest.fixture
def kc(monkeypatch):
    chave, privada = _gerar_par()
    chave_iam, privada_iam = _gerar_par()
    publica_iam = chave_iam.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    # Como no Keycloak, a JWKS traz também uma chave de cifragem (use=enc) —
    # aqui com o mesmo kid e na frente, para provar que ela é ignorada.
    cifragem, _ = _gerar_par()
    falsa = JwksFalsa({"keys": [_jwk(cifragem, use="enc"), _jwk(chave)]})
    monkeypatch.setattr(jwt_auth, "_baixar_jwks", falsa)
    monkeypatch.setattr(jwt_auth, "_jwks_cache", {})
    monkeypatch.setenv("KEYCLOAK_AP_ISSUER", ISSUER_KC)
    monkeypatch.delenv("KEYCLOAK_AP_AUDIENCE", raising=False)
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", publica_iam)
    monkeypatch.setenv("IAM_JWT_ISSUER", ISSUER_IAM)
    monkeypatch.delenv("IAM_JWT_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("IAM_JWT_PUBLIC_KEY", raising=False)
    return {"chave": chave, "privada": privada, "privada_iam": privada_iam, "jwks": falsa}


def _token_kc(privada, kid=KID, **overrides):
    agora = int(time.time())
    claims = {
        "iss": ISSUER_KC, "aud": ["ap-console", "account"], "azp": "ap-console",
        "sub": "58fb803a-16fe-4619-8f9c-f47747095cd2", "type": "access", "typ": "Bearer",
        "iat": agora, "exp": agora + 300, "financiador_id": FINANCIADOR,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return pyjwt.encode(claims, privada, algorithm="RS256", headers={"kid": kid})


def _bearer(token):
    return f"Bearer {token}"


def test_token_do_keycloak_valido_devolve_claims(kc):
    claims = validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    assert claims["financiador_id"] == FINANCIADOR
    assert claims["iss"] == ISSUER_KC


def test_aud_como_string_unica_tambem_vale(kc):
    validar_bearer_token(_bearer(_token_kc(kc["privada"], aud="ap-console")))


def test_aud_sem_ap_console_recusa(kc):
    with pytest.raises(JwtAuthError, match="inválido"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], aud=["account"])))


def test_aud_ausente_recusa(kc):
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], aud=None)))


def test_audience_configuravel_por_env(kc, monkeypatch):
    monkeypatch.setenv("KEYCLOAK_AP_AUDIENCE", "outro-client")
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    validar_bearer_token(_bearer(_token_kc(kc["privada"], aud=["outro-client"])))


def test_sub_ausente_recusa(kc):
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], sub=None)))


def test_sub_vazio_recusa(kc):
    with pytest.raises(JwtAuthError, match="sub"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], sub="  ")))


@pytest.mark.parametrize("tipo", [None, "refresh", "Bearer"])
def test_type_diferente_de_access_recusa(kc, tipo):
    with pytest.raises(JwtAuthError, match="acesso"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], type=tipo)))


def test_token_expirado_recusa(kc):
    with pytest.raises(JwtAuthError, match="expirado"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], exp=int(time.time()) - 10)))


def test_assinado_por_outra_chave_com_o_mesmo_kid_recusa(kc):
    _, intrusa = _gerar_par()
    with pytest.raises(JwtAuthError, match="inválido"):
        validar_bearer_token(_bearer(_token_kc(intrusa)))


def test_iss_de_outro_realm_nao_usa_a_jwks(kc):
    # Vai pelo caminho do IAM e cai na assinatura: nem toca na JWKS.
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], iss="https://auth.brikz.ai/realms/aml")))
    assert kc["jwks"].buscas == 0


def test_sem_keycloak_ap_issuer_token_do_keycloak_recusa(kc, monkeypatch):
    monkeypatch.delenv("KEYCLOAK_AP_ISSUER")
    with pytest.raises(JwtAuthError):
        validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    assert kc["jwks"].buscas == 0


def test_token_do_iam_continua_valendo_na_transicao(kc):
    agora = int(time.time())
    token = pyjwt.encode(
        {"iss": ISSUER_IAM, "sub": "7", "type": "access", "exp": agora + 300, "financiador_id": FINANCIADOR},
        kc["privada_iam"], algorithm="RS256",
    )
    assert validar_bearer_token(_bearer(token))["sub"] == "7"


def test_jwks_fica_em_cache(kc):
    for _ in range(3):
        validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    assert kc["jwks"].buscas == 1


def test_kid_desconhecido_busca_de_novo_uma_vez_e_recusa(kc, monkeypatch):
    validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    # Cache "velho" o bastante para permitir a busca forçada.
    url, (instante, jwks) = next(iter(jwt_auth._jwks_cache.items()))
    jwt_auth._jwks_cache[url] = (instante - 60, jwks)
    with pytest.raises(JwtAuthError, match="kid"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], kid="kid-inventado")))
    assert kc["jwks"].buscas == 2
    # Logo em seguida, outro kid inventado não busca de novo (intervalo mínimo).
    with pytest.raises(JwtAuthError, match="kid"):
        validar_bearer_token(_bearer(_token_kc(kc["privada"], kid="outro-kid")))
    assert kc["jwks"].buscas == 2


def test_rotacao_de_chave_no_keycloak(kc):
    validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    url, (instante, jwks) = next(iter(jwt_auth._jwks_cache.items()))
    jwt_auth._jwks_cache[url] = (instante - 60, jwks)
    nova, privada_nova = _gerar_par()
    kc["jwks"].jwks = {"keys": [_jwk(kc["chave"]), _jwk(nova, kid="kid-novo")]}
    validar_bearer_token(_bearer(_token_kc(privada_nova, kid="kid-novo")))


def test_keycloak_fora_do_ar_sem_cache_levanta_idp_indisponivel(kc):
    kc["jwks"].falhar = True
    with pytest.raises(IdpIndisponivel):
        validar_bearer_token(_bearer(_token_kc(kc["privada"])))


def test_keycloak_fora_do_ar_com_cache_vencido_usa_a_copia(kc):
    validar_bearer_token(_bearer(_token_kc(kc["privada"])))
    url, (instante, jwks) = next(iter(jwt_auth._jwks_cache.items()))
    jwt_auth._jwks_cache[url] = (instante - jwt_auth._JWKS_TTL_SEGUNDOS - 1, jwks)
    kc["jwks"].falhar = True
    validar_bearer_token(_bearer(_token_kc(kc["privada"])))


def _view_protegida():
    @jwt_required
    def view(request):
        return JsonResponse({"financiador_id": request.financiador_id, "sub": request.jwt_claims["sub"]})
    return view


def _chamar(token):
    request = RequestFactory().get("/", HTTP_AUTHORIZATION=_bearer(token))
    return _view_protegida()(request)


def test_jwt_required_aceita_token_do_keycloak(kc):
    resposta = _chamar(_token_kc(kc["privada"]))
    assert resposta.status_code == 200


def test_jwt_required_normaliza_financiador_id_numerico_para_str(kc):
    resposta = _chamar(_token_kc(kc["privada"], financiador_id=38138785000136))
    assert resposta.status_code == 200
    assert b'"financiador_id": "38138785000136"' in resposta.content


def test_jwt_required_sem_financiador_id_recusa(kc):
    assert _chamar(_token_kc(kc["privada"], financiador_id=None)).status_code == 401


def test_jwt_required_keycloak_fora_do_ar_responde_503(kc):
    kc["jwks"].falhar = True
    resposta = _chamar(_token_kc(kc["privada"]))
    assert resposta.status_code == 503
    assert b"IDP_INDISPONIVEL" in resposta.content
