import time
from datetime import datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "33777666000155"
URL = "/api/v1/agendas/urs/totais"
_FUSO = ZoneInfo("America/Sao_Paulo")
HOJE = datetime.now(_FUSO).date()
ONTEM = HOJE - timedelta(days=1)


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


def _linha_pagamento(cnpj_credenciadora: str, codigo_arranjo: str, tipo_informacao_pagamento: str, *, data_liquidacao_efetiva=None, valor_liquidacao_efetiva=None):
    return {
        "data_liquidacao": "2026-09-20",
        "entidade_registradora": "22246686000196",
        "cnpj_credenciadora": cnpj_credenciadora,
        "documento_ufr": UFR_TESTE,
        "documento_titular": UFR_TESTE,
        "codigo_arranjo": codigo_arranjo,
        "tipo_informacao_pagamento": tipo_informacao_pagamento,
        "data_liquidacao_efetiva": data_liquidacao_efetiva,
        "valor_liquidacao_efetiva": valor_liquidacao_efetiva,
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


def test_sem_ufr_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().get(URL, HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "CAMPO_OBRIGATORIO_AUSENTE"


def test_sem_dados_retorna_zeros(keypair):
    private_pem, _ = keypair
    response = Client().get(f"{URL}?ufr={UFR_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    corpo = response.json()
    assert Decimal(corpo["bloqueado"]) == Decimal("0")
    assert Decimal(corpo["disponivel"]) == Decimal("0")
    assert Decimal(corpo["liquidadoHoje"]) == Decimal("0")
    assert Decimal(corpo["totalALiquidar"]) == Decimal("0")


def test_bloqueado_disponivel_somam_passado_e_futuro_sem_fumaca(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    # Uma UR "passada" (data_liquidacao já não importa pra bloqueado/disponivel).
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCC", "1", 100, valor_bloqueado=30, valor_livre=70)).execute()
    # Outra constituída, valores diferentes.
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCD", "1", 50, valor_bloqueado=10, valor_livre=40)).execute()
    # Fumaça: nunca entra em bloqueado/disponivel/totalALiquidar.
    db.table("agenda_ur").insert(_linha_ur("BBB", "VCC", "2", 999, valor_bloqueado=999, valor_livre=0)).execute()

    response = Client().get(f"{URL}?ufr={UFR_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    corpo = response.json()
    assert Decimal(corpo["bloqueado"]) == Decimal("40.00")
    assert Decimal(corpo["disponivel"]) == Decimal("110.00")
    # Sem nenhuma confirmação de pagamento ainda: tudo que foi constituído falta liquidar.
    assert Decimal(corpo["totalALiquidar"]) == Decimal("150.00")


def test_liquidado_hoje_usa_confirmacao_real_nao_data_agendada(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCC", "1", 200, valor_bloqueado=0, valor_livre=200)).execute()
    # Confirmado HOJE — conta.
    db.table("agenda_ur_pagamento").insert(
        _linha_pagamento("AAA", "VCC", "1", data_liquidacao_efetiva=HOJE.isoformat(), valor_liquidacao_efetiva=80)
    ).execute()
    # Confirmado ONTEM — não conta em liquidadoHoje, mas reduz totalALiquidar.
    db.table("agenda_ur_pagamento").insert(
        _linha_pagamento("AAA", "VCC", "2", data_liquidacao_efetiva=ONTEM.isoformat(), valor_liquidacao_efetiva=50)
    ).execute()
    # Sem confirmação ainda (data_liquidacao_efetiva NULL) — não conta em nenhum dos dois.
    db.table("agenda_ur_pagamento").insert(
        _linha_pagamento("AAA", "VCC", "3", data_liquidacao_efetiva=None, valor_liquidacao_efetiva=None)
    ).execute()

    response = Client().get(f"{URL}?ufr={UFR_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    corpo = response.json()
    assert Decimal(corpo["liquidadoHoje"]) == Decimal("80.00")
    assert Decimal(corpo["totalALiquidar"]) == Decimal("200.00") - Decimal("80.00") - Decimal("50.00")


def test_filtro_por_credenciadora_e_arranjo(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_linha_ur("AAA", "VCC", "1", 100, valor_bloqueado=10, valor_livre=90)).execute()
    db.table("agenda_ur").insert(_linha_ur("CCC", "VCD", "1", 300, valor_bloqueado=20, valor_livre=280)).execute()

    response = Client().get(
        f"{URL}?ufr={UFR_TESTE}&credenciadora=AAA&arranjo=VCC",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert Decimal(corpo["bloqueado"]) == Decimal("10.00")
    assert Decimal(corpo["disponivel"]) == Decimal("90.00")
