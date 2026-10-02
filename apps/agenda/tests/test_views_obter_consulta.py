import time
from datetime import date

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client
from ulid import ULID

from apps.agenda import repository
from services.cerc.client import consultar_agenda
from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "22333444000181"
URL_CERC = "https://ap-homolog.cerc.inf.br/v15/agenda/consultar"


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


def _limpar():
    db = get_db(FINANCIADOR_TESTE)
    parcial = {"data_liquidacao": "2026-09-20", "entidade_registradora": "22246686000196"}
    campos = ("data_liquidacao", "entidade_registradora")
    repository._com_filtros(db.table("consulta_agenda_ur").delete(), parcial, campos).execute()
    repository._com_filtros(db.table("agenda_ur_evento").delete(), parcial, campos).execute()
    repository._com_filtros(db.table("agenda_ur_pagamento").delete(), parcial, campos).execute()
    repository._com_filtros(db.table("agenda_ur").delete(), parcial, campos).execute()
    db.table("consulta_agenda").delete().eq("filtro_ufr", UFR_TESTE).execute()
    db.table("cerc_requisicao").delete().eq("recurso", "agenda_consultar").execute()
    db.table("politica_consulta").delete().eq("motivo", "TESTE-VIEW-OBTER").execute()


@pytest.fixture(autouse=True)
def _ambiente(monkeypatch, keypair):
    _, public_pem = keypair
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", public_pem)
    monkeypatch.setenv("IAM_JWT_ISSUER", "brikz-iam")
    monkeypatch.setenv("CERC_API_BASE_URL", "https://ap-homolog.cerc.inf.br")

    from services.cerc import client as cerc_client
    monkeypatch.setattr(cerc_client, "get_cerc_token", lambda financiador_id: "token-teste")
    monkeypatch.setattr(cerc_client, "invalidate_token", lambda financiador_id: None)

    _limpar()
    db = get_db(FINANCIADOR_TESTE)
    db.table("politica_consulta").insert({
        "id": str(ULID()), "motivo": "TESTE-VIEW-OBTER", "modos_permitidos": ["BATCH", "ONLINE"], "ativo": True,
    }).execute()
    yield
    _limpar()


def _consulta_teste(**overrides):
    base = {
        "modo": "BATCH", "documento_ufr": UFR_TESTE, "documento_titular": None,
        "credenciadoras": ["99T"], "arranjos": ["99T"],
        "data_inicio": date(2026, 9, 1), "data_fim": date(2026, 9, 30),
        "tipo_avaliacao": None, "participante": None, "carteira": None,
        "base_autorizativa": {"tipo": "OPTIN", "id": "opt_1"},
        "motivo": "TESTE-VIEW-OBTER", "ator": "teste@teste.com", "origem_ip": None,
    }
    base.update(overrides)
    return base


def _resposta_cerc_com_uma_ur():
    return [{
        "entidadeRegistradora": "22246686000196",
        "instituicaoCredenciadora": "36216798000150",
        "codigoArranjoPagamento": "VCC",
        "documentoUsuarioFinalRecebedor": UFR_TESTE,
        "unidadesRecebiveis": [{
            "dataLiquidacao": "2026-09-20",
            "constituicao": "1",
            "valorTotalUR": 1000.0,
            "titulares": [{
                "documentoTitular": UFR_TESTE,
                "valorConstituidoTotal": 1000.0,
                "dataHoraUltimaAtualizacao": "2026-09-19T10:00:00.000Z",
                "pagamentos": [],
            }],
        }],
    }]


def test_sem_jwt_retorna_401():
    response = Client().get("/api/v1/agendas/consultas/01HZZZZZZZZZZZZZZZZZZZZZZZ")
    assert response.status_code == 401


def test_consulta_nao_encontrada_retorna_404(keypair):
    private_pem, _ = keypair
    response = Client().get(
        "/api/v1/agendas/consultas/01HZZZZZZZZZZZZZZZZZZZZZZZ",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 404


@respx.mock
def test_retorna_contagem_sincrono_e_frescor(keypair):
    private_pem, _ = keypair
    respx.post(URL_CERC).mock(return_value=httpx.Response(200, json=_resposta_cerc_com_uma_ur()))

    resultado = consultar_agenda(FINANCIADOR_TESTE, _consulta_teste())
    consulta_id = resultado["consultaId"]

    response = Client().get(
        f"/api/v1/agendas/consultas/{consulta_id}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert corpo["status"] == "COMPLETA"
    assert corpo["contagemPorOrigem"] == {"SINCRONO": 1, "WEBHOOK": 0, "ARQUIVO": 0}
    assert corpo["frescor"]["maisAntigo"] is not None
    assert corpo["frescor"]["maisRecente"] is not None


@respx.mock
def test_online_retorna_status_parcial_e_frescor_none_sem_urs(keypair):
    private_pem, _ = keypair
    respx.post(URL_CERC).mock(return_value=httpx.Response(200, json=[]))

    resultado = consultar_agenda(FINANCIADOR_TESTE, _consulta_teste(modo="ONLINE"))
    response = Client().get(
        f"/api/v1/agendas/consultas/{resultado['consultaId']}", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert corpo["status"] == "PARCIAL"
    assert corpo["contagemPorOrigem"] == {"SINCRONO": 0, "WEBHOOK": 0, "ARQUIVO": 0}
    assert corpo["frescor"] is None
