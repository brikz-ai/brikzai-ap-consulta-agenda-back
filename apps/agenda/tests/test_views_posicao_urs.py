import time
from decimal import Decimal

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "22888777000166"
URL = "/api/v1/agendas/urs/posicao"


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


def _linha_ur(cnpj_credenciadora: str, codigo_arranjo: str, constituicao: str, valor_total: float, valor_bloqueado=0, valor_livre=0):
    return {
        "entidade_registradora": "22246686000196",
        "cnpj_credenciadora": cnpj_credenciadora,
        "documento_ufr": UFR_TESTE,
        "documento_titular": UFR_TESTE,
        "codigo_arranjo": codigo_arranjo,
        "data_liquidacao": "2026-09-20",
        "constituicao": constituicao,
        "valor_constituido_total": valor_total,
        "valor_bloqueado": valor_bloqueado,
        "valor_livre": valor_livre,
        "valor_total_ur": valor_total,
        "data_hora_ultima_atualizacao": "2026-09-19T10:00:00-03:00",
        "origem": "SINCRONO",
    }


def _linha_pagamento(cnpj_credenciadora: str, codigo_arranjo: str, valor_onerado, tipo_informacao_pagamento: str):
    return {
        "data_liquidacao": "2026-09-20",
        "entidade_registradora": "22246686000196",
        "cnpj_credenciadora": cnpj_credenciadora,
        "documento_ufr": UFR_TESTE,
        "documento_titular": UFR_TESTE,
        "codigo_arranjo": codigo_arranjo,
        "tipo_informacao_pagamento": tipo_informacao_pagamento,
        "valor_onerado": valor_onerado,
        "domicilio": {},
    }


def _limpar():
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur_pagamento").delete().eq("documento_ufr", UFR_TESTE).execute()
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


def test_parametro_obrigatorio_ausente_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(f"{URL}?ufr={UFR_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "CAMPO_OBRIGATORIO_AUSENTE"


def test_agrega_por_credenciadora_arranjo_e_segrega_fumaca(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCC", "1", 100, valor_bloqueado=20, valor_livre=80)).execute()
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCD", "1", 50, valor_bloqueado=0, valor_livre=50)).execute()
    db.table("agenda_ur").insert(_linha_ur("BBB", "VCC", "2", 999, valor_bloqueado=0, valor_livre=0)).execute()  # fumaça
    db.table("agenda_ur_pagamento").insert(_linha_pagamento("AAA", "VCC", 30, "1")).execute()
    db.table("agenda_ur_pagamento").insert(_linha_pagamento("AAA", "VCC", 15, "2")).execute()

    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&dataLiquidacaoInicio=2026-09-01&dataLiquidacaoFim=2026-09-30",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()

    assert Decimal(corpo["valorTotalConstituido"]) == Decimal("150.00")
    assert Decimal(corpo["valorBloqueado"]) == Decimal("20.00")
    assert Decimal(corpo["valorLivre"]) == Decimal("130.00")
    assert Decimal(corpo["valorFumaca"]) == Decimal("999.00")
    assert Decimal(corpo["valorOnerado"]) == Decimal("45.00")

    por_credenciadora = {p["cnpjCredenciadora"]: Decimal(p["valorTotalConstituido"]) for p in corpo["porCredenciadora"]}
    assert por_credenciadora == {"AAA": Decimal("150.00")}  # BBB é só fumaça — não aparece aqui

    por_arranjo = {p["codigoArranjo"]: Decimal(p["valorTotalConstituido"]) for p in corpo["porArranjo"]}
    assert por_arranjo == {"VCC": Decimal("100.00"), "VCD": Decimal("50.00")}

    assert corpo["frescor"]["maisAntigo"] is not None
    assert corpo["frescor"]["maisRecente"] is not None


def test_sem_urs_no_periodo_retorna_zeros_e_frescor_none(keypair):
    private_pem, _ = keypair
    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&dataLiquidacaoInicio=2026-01-01&dataLiquidacaoFim=2026-01-31",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert Decimal(corpo["valorTotalConstituido"]) == Decimal("0")
    assert corpo["porCredenciadora"] == []
    assert corpo["porArranjo"] == []
    assert corpo["frescor"] is None
    # Os defaults quando não há linha na agregação precisam ser Decimal, não
    # int puro — senão o JSON emite número em vez de string (inconsistência
    # de tipo com o caso em que há dados, ver DjangoJSONEncoder/Decimal).
    assert isinstance(corpo["valorTotalConstituido"], str)
    assert isinstance(corpo["valorBloqueado"], str)
    assert isinstance(corpo["valorLivre"], str)
    assert isinstance(corpo["valorFumaca"], str)


def test_data_liquidacao_invalida_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&dataLiquidacaoInicio=ontem&dataLiquidacaoFim=2026-09-30",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"
