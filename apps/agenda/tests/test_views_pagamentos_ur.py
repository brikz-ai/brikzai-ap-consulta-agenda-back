import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from apps.agenda.repository import _CHAVE_UR, _com_filtros
from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "22999888000177"
URL = "/api/v1/agendas/urs/pagamentos"

CHAVE_TESTE = {
    "entidade_registradora": "22246686000196",
    "cnpj_credenciadora": "36216798000150",
    "documento_ufr": UFR_TESTE,
    "documento_titular": UFR_TESTE,
    "codigo_arranjo": "VCC",
    "data_liquidacao": "2026-09-20",
}

QUERY_TESTE = (
    f"entidadeRegistradora={CHAVE_TESTE['entidade_registradora']}"
    f"&credenciadora={CHAVE_TESTE['cnpj_credenciadora']}"
    f"&ufr={CHAVE_TESTE['documento_ufr']}"
    f"&titular={CHAVE_TESTE['documento_titular']}"
    f"&arranjo={CHAVE_TESTE['codigo_arranjo']}"
    f"&dataLiquidacao={CHAVE_TESTE['data_liquidacao']}"
)


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


def _agenda_ur():
    return {
        **CHAVE_TESTE,
        "constituicao": "1",
        "valor_constituido_total": 100,
        "valor_total_ur": 100,
        "data_hora_ultima_atualizacao": "2026-09-19T10:00:00-03:00",
        "origem": "SINCRONO",
    }


def _pagamento(tipo: str, **overrides):
    base = {
        **CHAVE_TESTE,
        "tipo_informacao_pagamento": tipo,
        "indicador_efeitos_contrato": "",
        "identificador_cerc_contrato": None,
        "regras_divisao": None,
        "valor_onerado": None,
        "valor_constituido_efeito": None,
        "valor_a_pagar": 100,
        "beneficiario": None,
        "data_liquidacao_efetiva": None,
        "valor_liquidacao_efetiva": None,
        "motivo_nao_pagamento": None,
        "domicilio": {"ispb": "00000000", "tipoConta": "CC", "numeroConta": "123-4"},
    }
    base.update(overrides)
    return base


def _limpar():
    db = get_db(FINANCIADOR_TESTE)
    _com_filtros(db.table("agenda_ur_pagamento").delete(), CHAVE_TESTE, _CHAVE_UR).execute()
    _com_filtros(db.table("agenda_ur").delete(), CHAVE_TESTE, _CHAVE_UR).execute()


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


def test_data_liquidacao_invalida_retorna_400(keypair):
    private_pem, _ = keypair
    query = QUERY_TESTE.replace("dataLiquidacao=2026-09-20", "dataLiquidacao=ontem")
    response = Client().get(f"{URL}?{query}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 400
    assert response.json()["erro"] == "PARAMETRO_INVALIDO"


def test_retorna_pagamentos_da_ur_identificada_pela_chave_natural(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_agenda_ur()).execute()
    db.table("agenda_ur_pagamento").insert(_pagamento("6")).execute()
    db.table("agenda_ur_pagamento").insert(_pagamento("7", indicador_efeitos_contrato="X")).execute()

    response = Client().get(f"{URL}?{QUERY_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    corpo = response.json()
    assert len(corpo["pagamentos"]) == 2
    tipos = {p["tipoInformacaoPagamento"] for p in corpo["pagamentos"]}
    assert tipos == {"6", "7"}
    pagamento_liquidacao = next(p for p in corpo["pagamentos"] if p["tipoInformacaoPagamento"] == "6")
    assert pagamento_liquidacao["domicilio"]["ispb"] == "00000000"
    assert pagamento_liquidacao["valorAPagar"] == 100


def test_ur_sem_pagamentos_retorna_lista_vazia_sem_erro(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_agenda_ur()).execute()

    response = Client().get(f"{URL}?{QUERY_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    assert response.json()["pagamentos"] == []


def test_nao_retorna_pagamentos_de_outra_ur(keypair):
    private_pem, _ = keypair
    db = get_db(FINANCIADOR_TESTE)
    db.table("agenda_ur").insert(_agenda_ur()).execute()
    db.table("agenda_ur_pagamento").insert(_pagamento("6")).execute()

    outra_chave = {**CHAVE_TESTE, "codigo_arranjo": "VCD"}
    db.table("agenda_ur").insert({**_agenda_ur(), "codigo_arranjo": "VCD"}).execute()
    db.table("agenda_ur_pagamento").insert({**_pagamento("7"), "codigo_arranjo": "VCD"}).execute()

    try:
        response = Client().get(f"{URL}?{QUERY_TESTE}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
        assert response.status_code == 200
        assert [p["tipoInformacaoPagamento"] for p in response.json()["pagamentos"]] == ["6"]
    finally:
        _com_filtros(db.table("agenda_ur_pagamento").delete(), outra_chave, _CHAVE_UR).execute()
        _com_filtros(db.table("agenda_ur").delete(), outra_chave, _CHAVE_UR).execute()
