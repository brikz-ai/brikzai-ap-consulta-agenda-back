import time
from datetime import date, datetime, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client
from ulid import ULID

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "22777666000155"
URL = "/api/v1/compliance/relatorio"


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


def _consulta(ator: str, iniciada_em: str):
    return {
        "id": str(ULID()),
        "modo": "BATCH", "status": "COMPLETA",
        "filtro_ufr": UFR_TESTE, "filtro_titular": None,
        "filtro_credenciadoras": ["99T"], "filtro_arranjos": ["99T"],
        "filtro_data_inicio": "2026-09-01", "filtro_data_fim": "2026-09-30",
        "base_autorizativa_tipo": "OPTIN", "base_autorizativa_id": "opt_1",
        "motivo": "TESTE-RELATORIO", "ator": ator, "origem_ip": "127.0.0.1",
        "iniciada_em": iniciada_em, "encerrada_em": iniciada_em,
    }


def _limpar():
    get_db(FINANCIADOR_TESTE).table("consulta_agenda").delete().eq("filtro_ufr", UFR_TESTE).execute()


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


def test_parametro_obrigatorio_ausente_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(URL, HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "CAMPO_OBRIGATORIO_AUSENTE"


def test_filtra_por_periodo_ufr_e_ator(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("consulta_agenda").insert(_consulta("analista.a@teste.com", "2026-09-10T10:00:00-03:00")).execute()
    db.table("consulta_agenda").insert(_consulta("analista.b@teste.com", "2026-09-15T10:00:00-03:00")).execute()
    db.table("consulta_agenda").insert(_consulta("analista.a@teste.com", "2026-08-01T10:00:00-03:00")).execute()  # fora do período

    response = Client().get(
        f"{URL}?dataInicio=2026-09-01&dataFim=2026-09-30&ufr={UFR_TESTE}",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert len(corpo["consultas"]) == 2
    assert {c["ator"] for c in corpo["consultas"]} == {"analista.a@teste.com", "analista.b@teste.com"}
    assert corpo["consultas"][0]["origemIp"] == "127.0.0.1"
    assert corpo["consultas"][0]["baseAutorizativaTipo"] == "OPTIN"

    filtrado_por_ator = Client().get(
        f"{URL}?dataInicio=2026-09-01&dataFim=2026-09-30&ufr={UFR_TESTE}&ator=analista.a@teste.com",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    corpo_ator = filtrado_por_ator.json()
    assert len(corpo_ator["consultas"]) == 1
    assert corpo_ator["consultas"][0]["ator"] == "analista.a@teste.com"


def test_paginacao_por_cursor(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("consulta_agenda").insert(_consulta("analista.a@teste.com", "2026-09-10T10:00:00-03:00")).execute()
    db.table("consulta_agenda").insert(_consulta("analista.b@teste.com", "2026-09-15T10:00:00-03:00")).execute()

    primeira = Client().get(
        f"{URL}?dataInicio=2026-09-01&dataFim=2026-09-30&ufr={UFR_TESTE}&limit=1",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    corpo1 = primeira.json()
    assert len(corpo1["consultas"]) == 1
    assert corpo1["proximoCursor"] is not None

    segunda = Client().get(
        f"{URL}?dataInicio=2026-09-01&dataFim=2026-09-30&ufr={UFR_TESTE}&limit=1&cursor={corpo1['proximoCursor']}",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    corpo2 = segunda.json()
    assert len(corpo2["consultas"]) == 1
    assert corpo2["consultas"][0]["consultaId"] != corpo1["consultas"][0]["consultaId"]
    assert corpo2["proximoCursor"] is None


def test_data_invalida_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(
        f"{URL}?dataInicio=nao-e-uma-data&dataFim=2026-09-30", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_janela_usa_fuso_america_sao_paulo_nao_utc(keypair):
    """Uma consulta às 22h (horário de Brasília) do último dia do período
    ainda está em 01h UTC do dia seguinte — se a janela fosse calculada em
    UTC (bug original), essa linha seria excluída de dataFim=2026-09-30."""
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    # 2026-09-30T22:00:00-03:00 == 2026-10-01T01:00:00Z
    db.table("consulta_agenda").insert(_consulta("analista.fronteira@teste.com", "2026-09-30T22:00:00-03:00")).execute()
    # 2026-10-01T00:30:00-03:00 (dia seguinte em SP) deve ficar fora da janela
    db.table("consulta_agenda").insert(_consulta("analista.fora@teste.com", "2026-10-01T00:30:00-03:00")).execute()

    response = Client().get(
        f"{URL}?dataInicio=2026-09-01&dataFim=2026-09-30&ufr={UFR_TESTE}",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    atores = {c["ator"] for c in response.json()["consultas"]}
    assert "analista.fronteira@teste.com" in atores
    assert "analista.fora@teste.com" not in atores
