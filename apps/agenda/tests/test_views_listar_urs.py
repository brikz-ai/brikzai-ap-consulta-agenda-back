import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "22999888000177"
URL = "/api/v1/agendas/urs"


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


def _token(private_pem):
    payload = {"exp": int(time.time()) + 300, "iss": "brikz-iam", "type": "access", "sub": "analista@teste.com", "financiador_id": FINANCIADOR_TESTE}
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def _linha(codigo_arranjo: str, data_liquidacao: str):
    return {
        "entidade_registradora": "22246686000196",
        "cnpj_credenciadora": "36216798000150",
        "documento_ufr": UFR_TESTE,
        "documento_titular": UFR_TESTE,
        "codigo_arranjo": codigo_arranjo,
        "data_liquidacao": data_liquidacao,
        "constituicao": "1",
        "valor_constituido_total": 100,
        "valor_total_ur": 100,
        "data_hora_ultima_atualizacao": "2026-09-19T10:00:00-03:00",
        "origem": "SINCRONO",
    }


def _limpar():
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").delete().eq("documento_ufr", UFR_TESTE).execute()


@pytest.fixture(autouse=True)
def _ambiente(monkeypatch, keypair):
    _, public_pem = keypair
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", public_pem)
    monkeypatch.setenv("IAM_JWT_ISSUER", "brikz-iam")
    _limpar()
    yield
    _limpar()


def test_sem_jwt_retorna_401():
    assert Client().get(URL).status_code == 401


def test_lista_filtrada_por_ufr(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha("VCC", "2026-09-20")).execute()
    db.table("agenda_ur").insert(_linha("VCD", "2026-09-21")).execute()

    response = Client().get(f"{URL}?ufr={UFR_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    corpo = response.json()
    assert len(corpo["urs"]) == 2
    assert corpo["proximoCursor"] is None
    assert {ur["codigoArranjo"] for ur in corpo["urs"]} == {"VCC", "VCD"}
    assert "sequencia" not in corpo["urs"][0]


def test_paginacao_por_cursor(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha("VCC", "2026-09-20")).execute()
    db.table("agenda_ur").insert(_linha("VCD", "2026-09-21")).execute()

    primeira = Client().get(f"{URL}?ufr={UFR_TESTE}&limit=1", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert primeira.status_code == 200
    corpo1 = primeira.json()
    assert len(corpo1["urs"]) == 1
    assert corpo1["proximoCursor"] is not None

    segunda = Client().get(
        f"{URL}?ufr={UFR_TESTE}&limit=1&cursor={corpo1['proximoCursor']}",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    corpo2 = segunda.json()
    assert len(corpo2["urs"]) == 1
    assert corpo2["urs"][0]["codigoArranjo"] != corpo1["urs"][0]["codigoArranjo"]
    assert corpo2["proximoCursor"] is None


def test_cursor_invalido_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(f"{URL}?cursor=abc", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_limit_acima_do_maximo_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(f"{URL}?limit=1001", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_filtro_data_liquidacao_intervalo_restringe_resultado(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha("VCA", "2026-09-10")).execute()
    db.table("agenda_ur").insert(_linha("VCC", "2026-09-20")).execute()
    db.table("agenda_ur").insert(_linha("VCE", "2026-09-30")).execute()

    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&dataLiquidacaoInicio=2026-09-15&dataLiquidacaoFim=2026-09-25",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert {ur["codigoArranjo"] for ur in corpo["urs"]} == {"VCC"}


def test_data_liquidacao_inicio_invalida_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&dataLiquidacaoInicio=ontem",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_atualizado_desde_invalido_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&atualizadoDesde=ontem",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_filtro_atualizado_desde_exclui_registro_mais_antigo(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert({**_linha("VCA", "2026-09-20"), "atualizado_em": "2026-01-01T00:00:00-03:00"}).execute()
    db.table("agenda_ur").insert({**_linha("VCC", "2026-09-21"), "atualizado_em": "2026-09-01T00:00:00-03:00"}).execute()

    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&atualizadoDesde=2026-06-01T00:00:00-03:00",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert {ur["codigoArranjo"] for ur in corpo["urs"]} == {"VCC"}
