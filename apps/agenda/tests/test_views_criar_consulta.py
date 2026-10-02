import json
import time

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client
from ulid import ULID

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
UFR_TESTE = "11222333000181"
URL = "/api/v1/agendas/consultas"
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


def _token(private_pem, **overrides):
    payload = {
        "exp": int(time.time()) + 300, "iss": "brikz-iam", "type": "access", "sub": "analista@teste.com",
        "financiador_id": FINANCIADOR_TESTE,
    }
    payload.update(overrides)
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def _limpar():
    db = get_db(FINANCIADOR_TESTE)
    db.table("consulta_agenda").delete().eq("filtro_ufr", UFR_TESTE).execute()
    db.table("cerc_requisicao").delete().eq("recurso", "agenda_consultar").execute()
    db.table("politica_consulta").delete().eq("motivo", "TESTE-VIEW-CONSULTAS").execute()


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
        "id": str(ULID()), "motivo": "TESTE-VIEW-CONSULTAS",
        "modos_permitidos": ["BATCH", "ONLINE"], "ativo": True,
    }).execute()
    yield
    _limpar()


def _corpo_consulta(**overrides):
    base = {
        "modo": "BATCH",
        "usuarioFinalRecebedor": UFR_TESTE,
        "credenciadoras": ["99T"],
        "arranjos": ["99T"],
        "dataInicio": "2026-09-01",
        "dataFim": "2026-09-30",
        "baseAutorizativa": {"tipo": "OPTIN", "id": "opt_1"},
        "motivo": "TESTE-VIEW-CONSULTAS",
    }
    base.update(overrides)
    return base


def test_sem_jwt_retorna_401():
    response = Client().post(URL, data=json.dumps(_corpo_consulta()), content_type="application/json")
    assert response.status_code == 401


def test_corpo_nao_json_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().post(
        URL, data="isto nao e json", content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "CORPO_INVALIDO"


def test_campo_obrigatorio_ausente_retorna_400(keypair):
    private_pem, _ = keypair
    corpo = _corpo_consulta()
    del corpo["motivo"]
    response = Client().post(
        URL, data=json.dumps(corpo), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "CAMPO_OBRIGATORIO_AUSENTE"


def test_modo_invalido_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().post(
        URL, data=json.dumps(_corpo_consulta(modo="ESTRANHO")), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "MODO_INVALIDO"


def test_base_autorizativa_nao_dict_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().post(
        URL, data=json.dumps(_corpo_consulta(baseAutorizativa="OPTIN")), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "DATA_INVALIDA"


def test_data_inicio_nao_string_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().post(
        URL, data=json.dumps(_corpo_consulta(dataInicio=20260901)), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "DATA_INVALIDA"


def test_politica_nao_configurada_retorna_403(keypair):
    private_pem, _ = keypair
    response = Client().post(
        URL, data=json.dumps(_corpo_consulta(motivo="MOTIVO-SEM-POLITICA")), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 403
    assert response.json()["erro"] == "POLITICA_NAO_CONFIGURADA"


@respx.mock
def test_batch_sucesso_retorna_200_e_persiste(keypair):
    private_pem, _ = keypair
    respx.post(URL_CERC).mock(return_value=httpx.Response(200, json=[]))

    response = Client().post(
        URL, data=json.dumps(_corpo_consulta()), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert corpo["status"] == "COMPLETA"
    assert corpo["agendas"] == []

    db = get_db(FINANCIADOR_TESTE)
    consulta = db.table("consulta_agenda").select("*").eq("id", corpo["consultaId"]).execute().data[0]
    assert consulta["modo"] == "BATCH"
    assert consulta["ator"] == "analista@teste.com"


@respx.mock
def test_online_sucesso_retorna_202(keypair):
    private_pem, _ = keypair
    respx.post(URL_CERC).mock(return_value=httpx.Response(200, json=[]))

    response = Client().post(
        URL, data=json.dumps(_corpo_consulta(modo="ONLINE")), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 202
    assert response.json()["status"] == "PARCIAL"


@respx.mock
def test_erro_critico_cerc_retorna_502(keypair):
    private_pem, _ = keypair
    respx.post(URL_CERC).mock(return_value=httpx.Response(401))

    response = Client().post(
        URL, data=json.dumps(_corpo_consulta()), content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 502
