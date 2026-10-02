import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from shared.cloudsql_client import get_db

FINANCIADOR_TESTE = "12345678000199"
URL = "/api/v1/config/politicas-consulta"


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
    payload = {"exp": int(time.time()) + 300, "iss": "brikz-iam", "type": "access", "sub": "admin@teste.com", "financiador_id": FINANCIADOR_TESTE}
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def _limpar():
    get_db(FINANCIADOR_TESTE).table("politica_consulta").delete().eq("motivo", "TESTE-POLITICA-VIEW").execute()


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


def test_metodo_nao_permitido_retorna_405(keypair):
    private_pem, _ = keypair
    response = Client().post(URL, HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 405


def test_put_cria_politica_nova(keypair):
    private_pem, _ = keypair
    response = Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["BATCH", "ONLINE"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    corpo = response.json()
    assert corpo["motivo"] == "TESTE-POLITICA-VIEW"
    assert corpo["modosPermitidos"] == ["BATCH", "ONLINE"]
    assert corpo["ativo"] is True


def test_put_atualiza_politica_existente_sem_duplicar(keypair):
    private_pem, _ = keypair
    Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["BATCH"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    response = Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["ONLINE"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 200
    assert response.json()["modosPermitidos"] == ["ONLINE"]

    db = get_db(FINANCIADOR_TESTE)
    linhas = db.table("politica_consulta").select("*").eq("motivo", "TESTE-POLITICA-VIEW").execute().data
    assert len(linhas) == 1


def test_put_modos_invalidos_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["ESTRANHO"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "MODOS_PERMITIDOS_INVALIDO"


def test_put_motivo_ausente_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().put(
        URL, data=json.dumps({"modosPermitidos": ["BATCH"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400


def test_put_corpo_nao_dict_retorna_400(keypair):
    private_pem, _ = keypair
    response = Client().put(
        URL, data=json.dumps(["not", "a", "dict"]),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    assert response.status_code == 400
    assert response.json()["erro"] == "CORPO_INVALIDO"


def test_get_lista_politicas(keypair):
    private_pem, _ = keypair
    Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["BATCH"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    response = Client().get(URL, HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    motivos = [p["motivo"] for p in response.json()["politicas"]]
    assert "TESTE-POLITICA-VIEW" in motivos


def test_delete_desativa_politica_sem_apagar(keypair):
    private_pem, _ = keypair
    Client().put(
        URL, data=json.dumps({"motivo": "TESTE-POLITICA-VIEW", "modosPermitidos": ["BATCH"]}),
        content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}",
    )
    response = Client().delete(f"{URL}?motivo=TESTE-POLITICA-VIEW", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 200
    assert response.json()["ativo"] is False

    db = get_db(FINANCIADOR_TESTE)
    linha = db.table("politica_consulta").select("*").eq("motivo", "TESTE-POLITICA-VIEW").execute().data[0]
    assert linha["ativo"] is False


def test_delete_politica_inexistente_retorna_404(keypair):
    private_pem, _ = keypair
    response = Client().delete(f"{URL}?motivo=NAO-EXISTE", HTTP_AUTHORIZATION=f"Bearer {_token(private_pem)}")
    assert response.status_code == 404
